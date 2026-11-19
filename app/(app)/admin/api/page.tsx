import type { Metadata } from 'next'
import { SubmitButton } from '@/components/client'
import {Card,Notice,PageHeader,Pill } from '@/components/ui'
import { TokenForm } from '@/components/token-form'
import { API_SCOPES, listTokens } from '@/lib/api-tokens'
import { requirePageRole } from '@/lib/auth/server'
import { appUrl } from '@/lib/config'
import { getPool } from '@/lib/db'
import { fmtDate, relTime } from '@/lib/format'
import { createApiTokenAction, createScimTokenAction, revokeTokenAction } from '../access-actions'
import { Notices } from '../shared'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'API & SCIM' }

const SCOPE_HELP: Record<(typeof API_SCOPES)[number], string> = {
  'domains:read': 'domain list, summary and volume over time',
  'reports:read': 'sending sources and failing sources',
  'dns:read': 'the latest DNS check',
}

export default async function ApiAccessPage({ searchParams }: { searchParams: Promise<{ error?: string; done?: string }> }) {
  const access = await requirePageRole('admin')
  const { error, done } = await searchParams
  const [api, scimTokens] = await Promise.all([listTokens(getPool(), 'api'), listTokens(getPool(), 'scim')])
  let base = ''
  try {
    base = appUrl().replace(/\/+$/, '')
  } catch {
    base = ''
  }
  const isOwner = access.role === 'owner'

  const row = (t: (typeof api)[number]) => (
    <div className="person-row" role="listitem" key={t.id}>
      <div className="person-who">
        <div className="source-name" style={{ overflowWrap: 'anywhere' }}>
          {t.name} <span className="muted small mono">{t.prefix}…</span>
        </div>
        <div className="source-meta">
          {t.kind === 'api' ? `${t.scopes.join(', ')} · ${t.domain_mode === 'all' ? 'every domain' : `${t.domains.length} domain(s)`}` : 'users and groups'} · by {t.created_by_email ?? 'someone removed'}
        </div>
        <div className="source-meta">
          {t.state === 'revoked' ? 'revoked' : `expires ${fmtDate(t.expires_at)}`} · {t.last_used_at ? `used ${relTime(t.last_used_at)}` : 'never used'}
        </div>
      </div>
      <div className="person-tags">
        <Pill tone={t.state === 'active' ? 'ok' : 'muted'}>{t.state}</Pill>
        {t.state === 'active' && (t.kind === 'api' || isOwner) && (
          <form action={revokeTokenAction} className="inline-form">
            <input type="hidden" name="id" value={t.id} />
            <SubmitButton className="btn btn-sm" pendingLabel="…">
              Revoke
            </SubmitButton>
          </form>
        )}
      </div>
    </div>
  )

  return (
    <>
      <PageHeader title="API & SCIM" lead="Read-only API tokens and the token your identity provider uses to provision people with SCIM." />
      <Notices error={error} done={done} />

      <section className="section" aria-labelledby="api-head">
        <div className="section-head">
          <h2 id="api-head">API tokens</h2>
        </div>
        <div className="card">
          <p className="small" style={{ marginTop: 0 }}>
            Send <code>Authorization: Bearer &lt;token&gt;</code> to <code>{base || 'https://your-app'}/api/v1/domains</code>. Tokens only read, expire, and
            stop working if their creator is disabled or is no longer an administrator.
          </p>
        </div>
        <div className="card flush" role="list" aria-label="API tokens" style={{ marginTop: '0.8rem' }}>
          {api.length === 0 && <div className="person-row muted">None yet.</div>}
          {api.map(row)}
        </div>
        <div className="card" style={{ marginTop: '0.8rem' }}>
          <h3 style={{ marginTop: 0 }}>New API token</h3>
          <TokenForm action={createApiTokenAction} submit="Create token">
            <div className="field">
              <label htmlFor="t-name">Name</label>
              <input id="t-name" name="name" type="text" maxLength={100} required placeholder="Reporting dashboard" />
            </div>
            <fieldset className="field">
              <legend className="small">Scopes</legend>
              {API_SCOPES.map((s) => (
                <label className="small" key={s} style={{ display: 'block' }}>
                  <input type="checkbox" name="scopes" value={s} defaultChecked /> <code>{s}</code> <span className="muted">{SCOPE_HELP[s]}</span>
                </label>
              ))}
            </fieldset>
            <fieldset className="field">
              <legend className="small">Domains</legend>
              <label className="small" style={{ display: 'block' }}>
                <input type="radio" name="mode" value="limited" defaultChecked /> Only these
              </label>
              <label className="small" style={{ display: 'block' }}>
                <input type="radio" name="mode" value="all" /> Every domain
              </label>
            </fieldset>
            <div className="field">
              <label htmlFor="t-domains">Allowed domains</label>
              <textarea id="t-domains" name="domains" rows={3} placeholder="example.com" />
              <div className="field-hint">One per line. With “Only these” and none listed, the token sees nothing.</div>
            </div>
            <div className="field">
              <label htmlFor="t-expires">Expires after (days)</label>
              <input id="t-expires" name="expires" type="text" inputMode="numeric" defaultValue="90" maxLength={3} />
              <div className="field-hint">1 to 365.</div>
            </div>
          </TokenForm>
        </div>
      </section>

      <section className="section" aria-labelledby="scim-head">
        <div className="section-head">
          <h2 id="scim-head">SCIM provisioning</h2>
        </div>
        <div className="card">
          <p className="small" style={{ marginTop: 0 }}>
            Point your identity provider’s SCIM client at <code>{base || 'https://your-app'}/scim/v2</code> with a bearer token. Provisioned people are viewers;
            SCIM cannot grant roles, change an e-mail address or touch an owner. Deactivating someone signs them out on their next request.
          </p>
          {!isOwner && <Notice tone="info" role="note">Only an owner can create or revoke the SCIM token.</Notice>}
        </div>
        <div className="card flush" role="list" aria-label="SCIM tokens" style={{ marginTop: '0.8rem' }}>
          {scimTokens.length === 0 && <div className="person-row muted">No SCIM token yet.</div>}
          {scimTokens.map(row)}
        </div>
        {isOwner && (
          <div className="card" style={{ marginTop: '0.8rem' }}>
            <h3 style={{ marginTop: 0 }}>New SCIM token</h3>
            <p className="small">Creating one ends the current token.</p>
            <TokenForm action={createScimTokenAction} submit="Create SCIM token">
              <div className="field">
                <label htmlFor="s-name">Name</label>
                <input id="s-name" name="name" type="text" maxLength={100} required placeholder="Okta" />
              </div>
              <div className="field">
                <label htmlFor="s-expires">Expires after (days)</label>
                <input id="s-expires" name="expires" type="text" inputMode="numeric" defaultValue="365" maxLength={3} />
              </div>
            </TokenForm>
          </div>
        )}
      </section>
    </>
  )
}
