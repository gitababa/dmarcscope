import type { Metadata } from 'next'
import { SubmitButton } from '@/components/client'
import {Card,Notice,PageHeader,Pill } from '@/components/ui'
import { listRules } from '@/lib/admin'
import { atLeast } from '@/lib/auth/roles'
import { requirePageRole } from '@/lib/auth/server'
import type { Role } from '@/lib/auth/types'
import { envBool, envList } from '@/lib/config'
import { addRuleAction, deleteRuleAction } from '../people-actions'
import { Notices, RoleSelect } from '../shared'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Access rules' }

const KIND_LABEL = { email_domain: 'Email domain', group: 'Group' } as const

// The environment lists, shown read-only: they cannot be changed here.
function environmentRules(): Array<{ variable: string; grants: string; values: string[] }> {
  const env = process.env
  const out = [
    { variable: 'ADMIN_EMAILS', grants: 'admin', values: envList(env.ADMIN_EMAILS) },
    { variable: 'ADMIN_GROUPS', grants: 'admin', values: envList(env.ADMIN_GROUPS) },
    { variable: 'ALLOWED_EMAILS', grants: 'viewer', values: envList(env.ALLOWED_EMAILS) },
    { variable: 'ALLOWED_EMAIL_DOMAINS', grants: 'viewer', values: envList(env.ALLOWED_EMAIL_DOMAINS) },
    { variable: 'ALLOWED_GROUPS', grants: 'viewer', values: envList(env.ALLOWED_GROUPS) },
  ].filter((r) => r.values.length > 0)
  if (envBool(env.AUTH_ALLOW_ANY_AUTHENTICATED)) {
    out.push({ variable: 'AUTH_ALLOW_ANY_AUTHENTICATED', grants: 'viewer', values: ['everyone the sign-in provider authenticates'] })
  }
  return out
}

export default async function AdminRulesPage({ searchParams }: { searchParams: Promise<{ error?: string; done?: string }> }) {
  const access = await requirePageRole('admin')
  const { error, done } = await searchParams
  const rules = await listRules(access)
  const fromEnv = environmentRules()

  return (
    <>
      <PageHeader title="Access rules" lead={<>Access rules let people in without adding them one by one. Someone signing in gets the highest role any rule
            gives them, re-evaluated on every request. Rules never make anyone an owner.</>} />
      <Notices error={error} done={done} />

      <Notice tone="warn" role="note">An email-domain rule is only as strong as your sign-in provider: with a shared provider such as Google, anyone
          with an account at that domain gets in, including personal accounts registered with a work address.</Notice>

      <section className="section" aria-labelledby="rules-head">
        <div className="section-head">
          <h2 id="rules-head">Rules</h2>
        </div>
        <div className="card flush" role="list" aria-label="Access rules">
          {rules.length === 0 && <div className="person-row muted">No rules yet.</div>}
          {rules.map((r) => (
            <div className="person-row" role="listitem" key={r.id}>
              <div className="person-who">
                <div className="source-name" style={{ overflowWrap: 'anywhere' }}>
                  {r.kind === 'email_domain' ? `anyone @${r.value}` : `members of “${r.value}”`}
                </div>
                <div className="source-meta">
                  {KIND_LABEL[r.kind]}
                  {r.created_by_email ? ` · added by ${r.created_by_email}` : ''}
                </div>
              </div>
              <div className="person-tags">
                <Pill tone={r.role === 'admin' ? 'info' : 'muted'}>{r.role}</Pill>
              </div>
              {atLeast(access.role, r.role as Role) && (
                <form action={deleteRuleAction}>
                  <input type="hidden" name="id" value={r.id} />
                  <input type="hidden" name="back" value="/admin/rules" />
                  <SubmitButton className="btn btn-sm">Delete</SubmitButton>
                </form>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="section" aria-labelledby="add-rule-head">
        <div className="section-head">
          <h2 id="add-rule-head">Add a rule</h2>
        </div>
        <div className="card">
          <form action={addRuleAction} className="inline-form">
            <input type="hidden" name="back" value="/admin/rules" />
            <label htmlFor="rule-kind" className="visually-hidden">
              Kind of rule
            </label>
            <select id="rule-kind" name="kind" defaultValue="email_domain">
              <option value="email_domain">Email domain</option>
              <option value="group">Group</option>
            </select>
            <label htmlFor="rule-value" className="visually-hidden">
              Domain or group name
            </label>
            <input id="rule-value" name="value" required maxLength={256} placeholder="example.com or group name" className="grow" />
            <RoleSelect actorRole={access.role} id="rule-role" includeOwner={false} label="Role the rule gives" />
            <SubmitButton className="btn btn-primary btn-sm">Add rule</SubmitButton>
          </form>
          <p className="muted small" style={{ marginBottom: 0 }}>
            Groups are matched against the groups your sign-in provider or proxy sends, without regard to case. Microsoft
            Entra ID sends group object IDs.
          </p>
        </div>
      </section>

      {fromEnv.length > 0 && (
        <section className="section" aria-labelledby="env-rules-head">
          <div className="section-head">
            <h2 id="env-rules-head">From the environment</h2>
          </div>
          <div className="card flush" role="list" aria-label="Rules from environment variables">
            {fromEnv.map((r) => (
              <div className="person-row" role="listitem" key={r.variable}>
                <div className="person-who">
                  <div className="source-name">{r.variable}</div>
                  <div className="source-meta" style={{ overflowWrap: 'anywhere' }}>
                    {r.values.join(', ')}
                  </div>
                </div>
                <div className="person-tags">
                  <Pill tone={r.grants === 'admin' ? 'info' : 'muted'}>{r.grants}</Pill>
                  <span className="muted small">managed by environment</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </>
  )
}
