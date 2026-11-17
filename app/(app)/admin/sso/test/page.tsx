import type { Metadata } from 'next'
import { Pill } from '@/components/ui'
import { requirePageRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { getConnection } from '@/lib/sso'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Sign-in test' }

const HINTS: Record<string, string> = {
  discovery:
    'The issuer could not be reached, or its discovery document did not match. Check the issuer URL (it must be exactly the issuer the provider publishes) and that this server can reach it.',
  provider:
    'The provider refused the sign-in. redirect_uri_mismatch means the redirect URI shown on the Sign-in page is not registered with the provider; invalid_client means a wrong client ID or secret.',
  exchange:
    'The provider sent you back, but exchanging the code failed. Most often the client secret is wrong, or the provider expects a different client authentication method.',
  unverified_email: 'The provider did not say the email address is verified. For Microsoft Entra ID use preferred_username as the email claim.',
  no_email: 'The configured email claim was missing or not an address. Check the email claim and the scopes.',
  wrong_account: 'A required claim was missing or had another value. Check the required claims.',
  failed: 'The provider’s answer was not a valid sign-in.',
}

// Shown in the window the test opened. The claims are the tester's own.
export default async function SsoTestPage() {
  await requirePageRole('owner')
  const draft = await getConnection(getPool(), 'draft')
  const t = draft?.last_test
  const current = t && draft && t.revision === draft.revision

  return (
    <div className="card" style={{ maxWidth: 720, margin: '0 auto' }}>
      <h1 style={{ marginTop: 0, fontSize: '1.3rem' }}>Single sign-on test</h1>
      {!t || !draft ? (
        <p>No test has been recorded for the current draft.</p>
      ) : (
        <>
          <p>
            {t.ok ? <Pill tone="ok">passed</Pill> : <Pill tone="bad">failed</Pill>}{' '}
            <span className="muted small">
              {new Date(t.at).toISOString().replace('T', ' ').slice(0, 19)} UTC · revision {t.revision}
              {current ? '' : ' (the draft has changed since: test again)'}
            </span>
          </p>
          {t.error && (
            <div className="notice bad" role="alert">
              <span>
                <strong>{t.error.code}</strong>: {t.error.message}
                {HINTS[t.error.code] && <div className="small" style={{ marginTop: '0.4rem' }}>{HINTS[t.error.code]}</div>}
              </span>
            </div>
          )}
          {t.identity && (
            <dl className="kv-list">
              <dt>Signed in as</dt>
              <dd>{t.identity.email}</dd>
              <dt>Groups kept</dt>
              <dd>{t.identity.groups.length ? t.identity.groups.join(', ') : 'none (only groups some rule names are kept)'}</dd>
              <dt>Would get in as</dt>
              <dd>
                {t.admission?.role ? (
                  <>
                    <Pill tone="info">{t.admission.role}</Pill> via {t.admission.via}
                  </>
                ) : (
                  <>
                    nobody admits this person{t.admission?.status === 'disabled' ? ' (disabled)' : ''}: they would become a pending
                    request
                  </>
                )}
              </dd>
            </dl>
          )}
          {t.claims && (
            <>
              <h2 style={{ fontSize: '1rem' }}>Claims the provider sent</h2>
              <div className="table-wrap">
                <table>
                  <tbody>
                    {Object.entries(t.claims).map(([k, v]) => (
                      <tr key={k}>
                        <th scope="row" style={{ textTransform: 'none' }}>
                          {k}
                        </th>
                        <td className="wrap">
                          <code>{typeof v === 'string' ? v : JSON.stringify(v)}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
      <p className="muted small" style={{ marginBottom: 0 }}>
        You can close this window and reload the Sign-in page. {t?.ok && current ? 'The draft can now be activated.' : ''}
      </p>
    </div>
  )
}
