#!/usr/bin/env node
// Re-encrypts every secret stored in the database under the current
// APP_SECRET. Part of rotating APP_SECRET:
//
//   1. set APP_SECRET to the new value and APP_SECRET_PREVIOUS to the old one,
//      and deploy (everything keeps working: old values decrypt with the
//      previous secret);
//   2. run this:  npm run secrets:reencrypt   (or node scripts/secrets-reencrypt.mjs)
//   3. remove APP_SECRET_PREVIOUS.
//
// All or nothing: if any value cannot be decrypted with either secret, the
// command changes nothing, names the records (never their values) and exits 1.
// --dry-run reports what it would do.

import pg from 'pg'
import { decrypt, encrypt } from '../lib/envelope.mjs'

async function main() {
  const dryRun = process.argv.includes('--dry-run')
  const url = process.env.DATABASE_URL
  const current = process.env.APP_SECRET || ''
  const previous = process.env.APP_SECRET_PREVIOUS || ''
  if (!url) {
    console.error('DATABASE_URL is not set.')
    process.exit(2)
  }
  if (current.length < 32 || (previous && previous.length < 32)) {
    console.error('APP_SECRET (and APP_SECRET_PREVIOUS, when set) must be at least 32 characters.')
    process.exit(2)
  }
  const secrets = previous ? [current, previous] : [current]

  const client = new pg.Client({ connectionString: url })
  await client.connect()
  const summary = { checked: 0, reencrypted: 0, failed: [], dry_run: dryRun }
  try {
    await client.query('BEGIN')
    const records = []
    for (const row of (await client.query(`SELECT key, value FROM settings WHERE is_secret FOR UPDATE`)).rows) {
      records.push({ name: `setting ${row.key}`, purpose: 'setting', context: row.key, envelope: row.value, table: 'settings', id: row.key })
    }
    for (const row of (await client.query(`SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL FOR UPDATE`)).rows) {
      records.push({ name: `user ${row.id} TOTP secret`, purpose: 'totp', context: `user:${row.id}`, envelope: row.totp_secret, table: 'users', id: row.id })
    }
    for (const row of (await client.query(`SELECT id, client_secret FROM sso_connections WHERE client_secret IS NOT NULL FOR UPDATE`)).rows) {
      records.push({ name: `SSO connection ${row.id} client secret`, purpose: 'setting', context: `sso:${row.id}`, envelope: row.client_secret, table: 'sso_connections', id: row.id })
    }
    // Mailbox secrets are only ever decrypted by the worker; rotation is the
    // one place this script reads them, to write them back under the new key.
    for (const row of (await client.query(`SELECT id, secret FROM mailboxes WHERE secret IS NOT NULL FOR UPDATE`)).rows) {
      records.push({ name: `mailbox ${row.id} secret`, purpose: 'mailbox', context: `mailbox:${row.id}`, envelope: row.secret, table: 'mailboxes', id: row.id })
    }

    const updates = []
    for (const r of records) {
      summary.checked++
      try {
        if (typeof r.envelope !== 'string') throw new Error('not an encrypted value')
        const { plaintext, keyIndex } = decrypt({ secrets, purpose: r.purpose, context: r.context, envelope: r.envelope })
        if (keyIndex > 0) updates.push({ ...r, envelope: encrypt({ secret: current, purpose: r.purpose, context: r.context, plaintext }) })
      } catch (err) {
        summary.failed.push(`${r.name}: ${err.code || err.message}`)
      }
    }
    if (summary.failed.length > 0) {
      await client.query('ROLLBACK')
      for (const f of summary.failed) console.error(`cannot decrypt ${f}`)
      console.error('Nothing was changed. Set APP_SECRET_PREVIOUS to the secret these were written with, or re-enter them in the panel.')
      console.log(JSON.stringify(summary))
      process.exitCode = 1
      return
    }
    for (const u of updates) {
      if (u.table === 'settings') await client.query(`UPDATE settings SET value = $2::jsonb, updated_at = NOW() WHERE key = $1`, [u.id, JSON.stringify(u.envelope)])
      else if (u.table === 'users') await client.query(`UPDATE users SET totp_secret = $2 WHERE id = $1`, [u.id, u.envelope])
      else if (u.table === 'sso_connections') await client.query(`UPDATE sso_connections SET client_secret = $2 WHERE id = $1`, [u.id, u.envelope])
      else await client.query(`UPDATE mailboxes SET secret = $2 WHERE id = $1`, [u.id, u.envelope])
    }
    summary.reencrypted = updates.length
    if (updates.length > 0) {
      await client.query('UPDATE config_version SET version = version + 1')
      await client.query(`INSERT INTO audit_log (action, detail) VALUES ('secrets_reencrypted', $1)`, [JSON.stringify({ count: updates.length })])
    }
    await client.query(dryRun ? 'ROLLBACK' : 'COMMIT')
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  } finally {
    await client.end()
  }
  console.error(
    dryRun
      ? `Dry run: ${summary.reencrypted} of ${summary.checked} secret(s) would be re-encrypted.`
      : `${summary.reencrypted} of ${summary.checked} secret(s) re-encrypted under APP_SECRET. You can now remove APP_SECRET_PREVIOUS.`
  )
  console.log(JSON.stringify(summary))
}

main().catch((err) => {
  console.error('Re-encryption failed:', err.message || err)
  process.exit(1)
})
