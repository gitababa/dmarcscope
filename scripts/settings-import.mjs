#!/usr/bin/env node
// Copies this environment's access lists into the database, so that they can
// be managed in the app and the variables deleted afterwards.
//
//   npm run settings:import
//   node scripts/settings-import.mjs [--dry-run]      (inside the container image)
//
//   ADMIN_EMAILS           → users, role admin
//   ALLOWED_EMAILS         → users, role viewer
//   ALLOWED_EMAIL_DOMAINS  → access rules (email domain → viewer)
//   ADMIN_GROUPS           → access rules (group → admin)
//   ALLOWED_GROUPS         → access rules (group → viewer)
//
// Idempotent: running it again changes nothing. It never lowers anyone's
// role, never touches the owner, and never re-enables a disabled user.
// AUTH_ALLOW_ANY_AUTHENTICATED has no database equivalent and stays an
// environment variable.

import pg from 'pg'

const list = (raw) =>
  (raw || '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean)

const EMAIL = /^[^@\s,]+@[^@\s,]+$/
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/

async function main() {
  const dryRun = process.argv.includes('--dry-run')
  const url = process.env.DATABASE_URL
  if (!url) {
    console.error('DATABASE_URL is not set.')
    process.exit(2)
  }
  const provider = (process.env.AUTH_PROVIDER || '').trim().toLowerCase()
  const source = provider === 'proxy-jwt' || provider === 'proxy-header' ? 'proxy' : 'oidc'

  const admins = list(process.env.ADMIN_EMAILS)
  const viewers = list(process.env.ALLOWED_EMAILS).filter((e) => !admins.includes(e))
  const domains = list(process.env.ALLOWED_EMAIL_DOMAINS)
  const adminGroups = list(process.env.ADMIN_GROUPS)
  const viewerGroups = list(process.env.ALLOWED_GROUPS).filter((g) => !adminGroups.includes(g))

  const skipped = [
    ...[...admins, ...viewers].filter((e) => !EMAIL.test(e)).map((e) => `not an email address: ${e}`),
    ...domains.filter((d) => !DOMAIN.test(d)).map((d) => `not a domain name: ${d}`),
  ]
  const summary = { users_added: 0, users_updated: 0, rules_added: 0, rules_updated: 0, skipped, dry_run: dryRun }

  const client = new pg.Client({ connectionString: url })
  await client.connect()
  try {
    await client.query('BEGIN')
    const upsertUser = async (email, role) => {
      // Insert, or raise a lower role to this one; never the owner, never a
      // disabled account, never downwards.
      const { rows } = await client.query(
        `INSERT INTO users (email, role, role_source, status, source)
         VALUES ($1, $2, 'assigned', 'active', $3)
         ON CONFLICT (email) DO UPDATE SET
           role = CASE WHEN users.role = 'viewer' OR users.role_source = 'rule' THEN EXCLUDED.role ELSE users.role END,
           role_source = 'assigned',
           status = CASE WHEN users.status = 'pending' THEN 'active' ELSE users.status END
         WHERE users.role <> 'owner' AND users.status <> 'disabled'
           AND (users.role_source = 'rule' OR users.status = 'pending' OR (users.role = 'viewer' AND EXCLUDED.role = 'admin'))
         RETURNING (xmax = 0) AS inserted`,
        [email, role, source]
      )
      if (rows[0]?.inserted) summary.users_added++
      else if (rows[0]) summary.users_updated++
    }
    for (const e of viewers.filter((x) => EMAIL.test(x))) await upsertUser(e, 'viewer')
    for (const e of admins.filter((x) => EMAIL.test(x))) await upsertUser(e, 'admin')

    const upsertRule = async (kind, value, role) => {
      const { rows } = await client.query(
        `INSERT INTO access_rules (kind, value, role) VALUES ($1, $2, $3)
         ON CONFLICT (kind, value) DO UPDATE SET role = EXCLUDED.role
         WHERE access_rules.role = 'viewer' AND EXCLUDED.role = 'admin'
         RETURNING (xmax = 0) AS inserted`,
        [kind, value, role]
      )
      if (rows[0]?.inserted) summary.rules_added++
      else if (rows[0]) summary.rules_updated++
    }
    for (const d of domains.filter((x) => DOMAIN.test(x))) await upsertRule('email_domain', d, 'viewer')
    for (const g of adminGroups) await upsertRule('group', g, 'admin')
    for (const g of viewerGroups) await upsertRule('group', g, 'viewer')

    const changed = summary.users_added + summary.users_updated + summary.rules_added + summary.rules_updated
    if (changed > 0) {
      await client.query('UPDATE config_version SET version = version + 1')
      await client.query(`INSERT INTO audit_log (action, detail) VALUES ('settings_imported', $1)`, [
        JSON.stringify({ users_added: summary.users_added, users_updated: summary.users_updated, rules_added: summary.rules_added, rules_updated: summary.rules_updated }),
      ])
    }
    await client.query(dryRun ? 'ROLLBACK' : 'COMMIT')
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  } finally {
    await client.end()
  }

  for (const s of skipped) console.error(`skipped (${s})`)
  if (process.env.AUTH_ALLOW_ANY_AUTHENTICATED) {
    console.error('AUTH_ALLOW_ANY_AUTHENTICATED has no equivalent in the database: keep it in the environment.')
  }
  console.error(
    dryRun
      ? 'Dry run: nothing was written.'
      : 'Done. The imported lists keep working from the database; you can now remove ADMIN_EMAILS, ALLOWED_EMAILS, ALLOWED_EMAIL_DOMAINS, ADMIN_GROUPS and ALLOWED_GROUPS from the environment.'
  )
  console.log(JSON.stringify(summary))
}

main().catch((err) => {
  console.error('Import failed:', err.message || err)
  process.exit(1)
})
