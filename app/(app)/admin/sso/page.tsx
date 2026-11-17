import type { Metadata } from 'next'
import { FocusedSubmitButton, SubmitButton } from '@/components/client'
import { Pill } from '@/components/ui'
import { listPendingRequests } from '@/lib/admin'
import { authProvider } from '@/lib/auth'
import { redirectUri } from '@/lib/auth/oidc'
import { atLeast } from '@/lib/auth/roles'
import { requirePageRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { relTime } from '@/lib/format'
import { configStore } from '@/lib/settings'
import { type ConnectionRow, PRESETS, type Preset, activationProblem, getConnection } from '@/lib/sso'
import { updateSettingAction } from '../actions'
import { AdminNav } from '../nav'
import { activateAction, deactivateAction, discardDraftAction, saveDraftAction, startDraftAction } from '../sso-actions'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Sign-in' }

const ERRORS: Record<string, string> = {
  not_allowed: 'Only the owner can change how people sign in.',
  invalid: 'That value is not valid.',
  no_draft: 'There is no draft any more. This is the current state.',
  no_active: 'No connection is active.',
  not_tested: 'Test the draft (as it is saved now) before activating it.',
  test_failed: 'The last test failed. Fix the draft, save it and test again.',
  test_stale: 'The last test is more than a day old. Test again before activating.',
  environment: 'Single sign-on is managed by environment variables on this deployment.',
  owner_only: 'Only the owner can change how people sign in.',
  managed_by_environment: 'That switch is set by an environment variable and cannot be changed here.',
}

const FIELD: Record<string, string> = {
  preset: 'provider',
  issuer: 'Issuer (https, the full issuer URL with the placeholders filled in)',
  client_id: 'Client ID',
  client_secret: 'Client secret',
  scopes: 'Scopes (must include openid)',
  email_claim: 'Email claim',
  groups_claim: 'Groups claim',
  required_claims: 'Required claims (claim=value,other=a|b)',
  button_label: 'Button label (60 characters at most)',
}

const DONE: Record<string, string> = {
  editing: 'Editing a draft. Nothing changes for anyone until you test and activate it.',
  saved: 'Draft saved. Test it before activating: saving changes nothing for anyone.',
  discarded: 'Draft discarded.',
  activated: 'Activated. The sign-in page offers it within a few seconds on every instance.',
  deactivated: 'Deactivated. People sign in with a password again; the owner always can.',
  switched: 'Saved. It applies within a few seconds on every instance.',
}

export default async function AdminSsoPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; field?: string; done?: string; confirm?: string }>
}) {
  const access = await requirePageRole('admin')
  const isOwner = atLeast(access.role, 'owner')
  const { error, field, done, confirm } = await searchParams
  const db = getPool()
  const provider = authProvider()
  const [pending, draft, active, settings] = await Promise.all([
    listPendingRequests(access),
    getConnection(db, 'draft'),
    getConnection(db, 'active'),
    configStore().list(),
  ])
  const switches = settings.filter((s) => s.key === 'auth.local_signin_non_owners' || s.key === 'auth.enforce_sso')

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <p>
            How people sign in. The owner can always sign in with their password and authenticator, whatever is set
            here, so a broken connection never locks you out.
          </p>
        </div>
      </div>
      <AdminNav current="/admin/sso" pending={pending.length} />

      {error && (
        <div className="notice bad" role="alert">
          {ERRORS[error] ?? 'That could not be done.'}
          {error === 'invalid' && field && FIELD[field] ? ` Check: ${FIELD[field]}.` : ''}
        </div>
      )}
      {done && !error && DONE[done] && (
        <div className="notice ok" role="status">
          {DONE[done]}
        </div>
      )}

      {provider === 'oidc' && (
        <div className="card">
          <p style={{ marginTop: 0 }}>
            Single sign-on is <strong>managed by environment</strong> on this deployment (<code>AUTH_PROVIDER=oidc</code>).
          </p>
          <dl className="kv-list">
            <dt>Issuer</dt>
            <dd>{process.env.OIDC_ISSUER}</dd>
            <dt>Client ID</dt>
            <dd>{process.env.OIDC_CLIENT_ID}</dd>
            <dt>Redirect URI</dt>
            <dd>
              <code>{redirectUri()}</code>
            </dd>
          </dl>
          <p className="muted small" style={{ marginBottom: 0 }}>
            To manage it here instead, set it up here first and then remove <code>AUTH_PROVIDER</code> and the{' '}
            <code>OIDC_*</code> variables (see docs/sso.md).
          </p>
        </div>
      )}

      {(provider === 'proxy-jwt' || provider === 'proxy-header' || provider === 'none') && (
        <div className="card">
          <p style={{ margin: 0 }}>
            People sign in through the access proxy in front of this app (<code>AUTH_PROVIDER={provider}</code>), so there is
            nothing to configure here.
          </p>
        </div>
      )}

      {provider === 'local' && (
        <>
          <section className="section" aria-labelledby="active-head">
            <div className="section-head">
              <h2 id="active-head">Active connection</h2>
            </div>
            <div className="card">
              {active ? (
                <>
                  <Summary c={active} />
                  <p className="muted small">Activated {active.activated_at ? relTime(active.activated_at) : ''}.</p>
                  {isOwner &&
                    (confirm === 'deactivate' ? (
                      <form action={deactivateAction} className="notice bad confirm" role="alert">
                        <input type="hidden" name="confirm" value="yes" />
                        <span>
                          Deactivate single sign-on? Everyone but the owner loses the sign-in button; existing sessions
                          stay valid.
                        </span>
                        <span className="inline-form">
                          <FocusedSubmitButton className="btn btn-sm">Yes, deactivate</FocusedSubmitButton>
                          <a href="/admin/sso" className="small">
                            Cancel
                          </a>
                        </span>
                      </form>
                    ) : (
                      <form action={deactivateAction}>
                        <SubmitButton className="btn btn-sm">Deactivate…</SubmitButton>
                      </form>
                    ))}
                </>
              ) : (
                <p style={{ margin: 0 }}>None. People sign in with a password (the owner only, unless enabled below).</p>
              )}
            </div>
          </section>

          <section className="section" aria-labelledby="draft-head">
            <div className="section-head">
              <h2 id="draft-head">{active ? 'Change the connection' : 'Set up single sign-on'}</h2>
            </div>
            <div className="card">
              <p className="muted small" style={{ marginTop: 0 }}>
                Register this redirect URI with your provider: <code className="wrap">{redirectUri()}</code>
              </p>
              {!draft && isOwner && (
                <form action={startDraftAction} className="inline-form">
                  {!active && (
                    <>
                      <label htmlFor="preset">Provider</label>
                      <select id="preset" name="preset" defaultValue="google">
                        {(Object.keys(PRESETS) as Preset[]).map((p) => (
                          <option key={p} value={p}>
                            {p === 'generic' ? 'Other OpenID Connect provider' : PRESETS[p].label}
                          </option>
                        ))}
                      </select>
                    </>
                  )}
                  <SubmitButton className="btn btn-sm btn-primary">{active ? 'Edit a copy' : 'Start'}</SubmitButton>
                </form>
              )}
              {!draft && !isOwner && <p className="muted">Only the owner can change how people sign in.</p>}
              {draft && <DraftEditor draft={draft} isOwner={isOwner} />}
            </div>
          </section>
        </>
      )}

      <section className="section" aria-labelledby="switches-head">
        <div className="section-head">
          <h2 id="switches-head">Password sign-in</h2>
        </div>
        <div className="card flush">
          {switches.map((s) => (
            <div className="setting-row" key={s.key}>
              <div>
                <div className="source-name">{s.label}</div>
                <div className="muted small">{s.description}</div>
              </div>
              <div>
                <Pill tone={s.value ? 'info' : 'muted'}>{s.value ? 'on' : 'off'}</Pill>{' '}
                {s.source === 'environment' && <span className="muted small">managed by environment ({s.envVar})</span>}
                {s.error && <div className="tone-bad small">invalid: {s.error}</div>}
              </div>
              {isOwner && s.source !== 'environment' ? (
                <form action={updateSettingAction} className="settings-edit">
                  <input type="hidden" name="key" value={s.key} />
                  <input type="hidden" name="back" value="/admin/sso" />
                  <input type="hidden" name="value" value={s.value ? 'false' : 'true'} />
                  <SubmitButton className="btn btn-sm">{s.value ? 'Turn off' : 'Turn on'}</SubmitButton>
                </form>
              ) : (
                <span />
              )}
            </div>
          ))}
        </div>
      </section>
    </>
  )
}

function Summary({ c }: { c: ConnectionRow }) {
  return (
    <dl className="kv-list">
      <dt>Provider</dt>
      <dd>{c.preset === 'generic' ? 'OpenID Connect' : PRESETS[c.preset as Preset]?.label ?? c.preset}</dd>
      <dt>Issuer</dt>
      <dd>{c.issuer}</dd>
      <dt>Client ID</dt>
      <dd>{c.client_id}</dd>
      <dt>Client secret</dt>
      <dd>{c.client_secret ? 'set' : 'none (public client, PKCE only)'}</dd>
      <dt>Address from</dt>
      <dd>
        <code>{c.email_claim}</code>
        {c.email_claim === 'email' ? ' (must be verified)' : ''}
      </dd>
      <dt>Groups from</dt>
      <dd>
        <code>{c.groups_claim}</code>
      </dd>
      <dt>Required claims</dt>
      <dd>{c.required_claims ? <code>{c.required_claims}</code> : 'none'}</dd>
      <dt>Button</dt>
      <dd>{c.button_label || 'Sign in with single sign-on'}</dd>
    </dl>
  )
}

function DraftEditor({ draft, isOwner }: { draft: ConnectionRow; isOwner: boolean }) {
  const preset = (draft.preset as Preset) in PRESETS ? (draft.preset as Preset) : 'generic'
  const problem = activationProblem(draft)
  const t = draft.last_test
  const testedThis = t && t.revision === draft.revision

  return (
    <>
      <div className="notice" role="note">
        <span>{PRESETS[preset].note}</span>
      </div>
      <form action={saveDraftAction} className="form">
        <div className="field">
          <label htmlFor="d-preset">Provider</label>
          <select id="d-preset" name="preset" defaultValue={preset} disabled={!isOwner}>
            {(Object.keys(PRESETS) as Preset[]).map((p) => (
              <option key={p} value={p}>
                {p === 'generic' ? 'Other OpenID Connect provider' : PRESETS[p].label}
              </option>
            ))}
          </select>
        </div>
        <Field id="issuer" label="Issuer" value={draft.issuer} hint="Replace the capitalised parts with your own values." readOnly={!isOwner} required />
        <Field id="client_id" label="Client ID" value={draft.client_id} readOnly={!isOwner} required />
        <div className="field">
          <label htmlFor="client_secret">Client secret</label>
          <input
            id="client_secret"
            name="client_secret"
            type="password"
            autoComplete="off"
            placeholder={draft.client_secret ? 'set; type to replace' : 'not set'}
            readOnly={!isOwner}
          />
          <label className="small muted">
            <input type="checkbox" name="public_client" value="1" disabled={!isOwner} /> No secret (public client, PKCE only)
          </label>
        </div>
        <Field id="scopes" label="Scopes" value={draft.scopes} readOnly={!isOwner} required />
        <Field id="email_claim" label="Email claim" value={draft.email_claim} hint="The one claim the address is read from. With email, the provider must say it is verified." readOnly={!isOwner} required />
        <Field id="groups_claim" label="Groups claim" value={draft.groups_claim} readOnly={!isOwner} required />
        <Field
          id="required_claims"
          label="Required claims"
          value={draft.required_claims}
          hint="Every sign-in must carry these, e.g. hd=example.com (Google Workspace) or tid=<tenant id>. claim=value, separated by commas; | between alternatives."
          readOnly={!isOwner}
        />
        <Field id="button_label" label="Button label" value={draft.button_label} hint='Shown as "Sign in with …".' readOnly={!isOwner} />
        {isOwner && (
          <div className="inline-form">
            <SubmitButton className="btn btn-primary btn-sm">Save draft</SubmitButton>
          </div>
        )}
      </form>

      <div className="test-box" aria-live="polite">
        <h3>Test and activate</h3>
        <p className="small">
          {!t || !testedThis ? (
            <>Not tested yet (revision {draft.revision}).</>
          ) : t.ok ? (
            <>
              <Pill tone="ok">test passed</Pill> {relTime(t.at)} as <strong>{t.identity?.email}</strong>.
            </>
          ) : (
            <>
              <Pill tone="bad">test failed</Pill> {relTime(t.at)}: {t.error?.message}
            </>
          )}{' '}
          {t && testedThis && (
            <a href="/admin/sso/test" target="_blank" rel="noopener">
              Details
            </a>
          )}
        </p>
        {isOwner && (
          <div className="inline-form">
            <a className="btn btn-sm" href="/auth/sso-test" target="_blank" rel="noopener">
              Test sign-in (opens a new window)
            </a>
            <form action={activateAction}>
              <SubmitButton className={`btn btn-sm${problem ? '' : ' btn-primary'}`}>Activate</SubmitButton>
            </form>
            <form action={discardDraftAction}>
              <SubmitButton className="btn btn-sm">Discard draft</SubmitButton>
            </form>
          </div>
        )}
        <p className="muted small" style={{ marginBottom: 0 }}>
          A test signs you in at the provider and shows what came back; it does not change your session. Only a passed
          test of the draft as saved can activate it. Reload this page after testing.
        </p>
      </div>
    </>
  )
}

function Field({ id, label, value, hint, readOnly, required }: { id: string; label: string; value: string; hint?: string; readOnly?: boolean; required?: boolean }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} name={id} type="text" defaultValue={value} readOnly={readOnly} required={required} spellCheck={false} autoComplete="off" />
      {hint && <span className="field-hint">{hint}</span>}
    </div>
  )
}
