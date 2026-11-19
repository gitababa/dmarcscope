import type { Metadata } from 'next'
import { cookies } from 'next/headers'
import { notFound } from 'next/navigation'
import { DeploymentGuide } from '@/components/deploy-guide'
import { BrandMark, Notice } from '@/components/ui'
import { authProvider } from '@/lib/auth'
import { PASSWORD_MIN } from '@/lib/auth/password-policy'
import { purposeCookieName } from '@/lib/auth/session'
import { otpauthUri } from '@/lib/crypto'
import { getPool } from '@/lib/db'
import { detectPlatform } from '@/lib/deploy-guide'
import { qrPath } from '@/lib/qr'
import { getAppName } from '@/lib/settings'
import { REISSUE_COOLDOWN_SECONDS, type SetupTokenStatus, ensureSetupToken, ownerExists, setupTokenStatus } from '@/lib/setup'
import { unsealSetupState } from '@/lib/setup-state'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Set up' }

const ERRORS: Record<string, string> = {
  form: 'The form could not be read. Please try again.',
  expired: 'This setup session expired. Start again with the setup token.',
  locked: 'Too many wrong attempts from this address. Wait a few minutes and try again.',
  token_invalid: 'That setup token is not valid. Copy it again from the server log, or from SETUP_TOKEN.',
  token_expired: 'That setup token has expired. Restart the app (or reload this page) to have a new one written to the server log.',
  token_used: 'That setup token has already been used.',
  token_cooldown: `A new token was written to the log less than ${REISSUE_COOLDOWN_SECONDS} seconds ago. Look for it in the log, or try again in a minute.`,
  email: 'Enter a valid email address.',
  password_short: `The password must be at least ${PASSWORD_MIN} characters long.`,
  password_long: 'The password is too long (256 characters at most).',
  password_common: 'That password is too common or too simple. Choose another.',
  password_email: 'The password must not be your email address.',
  password_mismatch: 'The two passwords do not match.',
  proxy_identity: 'This deployment signs people in through an access proxy, and this request did not carry an identity from it.',
  code: 'That code is not right. Check the time on your phone and enter the current code.',
  app_secret: 'APP_SECRET is not set (or shorter than 32 characters). Set it on the server and restart, then start setup again.',
}

const STEPS = ['Setup token', 'Owner account', 'Authenticator']

export default async function SetupPage({ searchParams }: { searchParams: Promise<{ error?: string; done?: string }> }) {
  const db = getPool()
  if (await ownerExists(db)) notFound()

  const { error, done } = await searchParams
  const noSecret = (process.env.APP_SECRET || '').length < 32
  const state = noSecret ? null : await unsealSetupState((await cookies()).get(purposeCookieName('setup'))?.value)
  const appName = await getAppName()

  if (!state) {
    // Mint (and log) a token if none is usable: after the first one expired,
    // opening this page is enough to get a new one.
    try {
      await ensureSetupToken(db)
    } catch (err) {
      console.error('[setup] could not create a setup token:', err instanceof Error ? err.message : String(err))
    }
  }

  const tokenStatus = !state && !noSecret ? await setupTokenStatus(db).catch(() => null) : null
  const current = !state ? 0 : state.step === 'account' ? 1 : 2
  const message = noSecret ? ERRORS.app_secret : error ? (ERRORS[error] ?? ERRORS.form) : null
  const proxied = ['proxy-jwt', 'proxy-header'].includes(authProvider())

  return (
    <main className="auth-wrap">
      <div className="card auth-card wide">
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
          <BrandMark size={24} />
          <DeploymentGuide detected={detectPlatform()} className="btn btn-sm btn-ghost" />
        </div>
        <h1>Set up {appName}</h1>
        <div className="wizard-steps" aria-label="Setup progress">
          {STEPS.map((s, i) => (
            <span key={s} className={i < current ? 'done' : undefined} aria-current={i === current ? 'step' : undefined}>
              {i + 1}. {s}
            </span>
          ))}
        </div>
        {message && (
          <Notice tone={error === 'token_cooldown' && !noSecret ? 'info' : 'bad'} role="alert">
            {message}
          </Notice>
        )}

        {current === 0 && done === 'new_token' && !message && (
          <Notice tone="ok" role="status">
            A new setup token was written to the server log just now. Look for the newest line starting with <code>[setup]</code>.
          </Notice>
        )}

        {current === 0 && !noSecret && (
          <>
            <p>
              Create the owner account. The owner can always sign in with a password and an authenticator app, even
              when single sign-on is not set up or not working.
            </p>
            <form className="form" method="post" action="/setup/token">
              <div className="field">
                <label htmlFor="token">Setup token</label>
                <input id="token" name="token" type="password" autoComplete="off" required autoFocus spellCheck={false} />
              </div>
              <button className="btn btn-primary btn-block" type="submit">
                Continue
              </button>
            </form>
            {tokenStatus && <WhereIsTheToken status={tokenStatus} />}
          </>
        )}

        {state?.step === 'account' && (
          <form className="form" method="post" action="/setup/account">
            <div className="field">
              <label htmlFor="email">Email address</label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                required
                autoFocus={!proxied}
                disabled={proxied}
                defaultValue={state.draft?.email}
              />
              {proxied && <span className="field-hint">The address your access proxy signs you in with is used.</span>}
            </div>
            <div className="field">
              <label htmlFor="name">Name (optional)</label>
              <input id="name" name="name" type="text" autoComplete="name" maxLength={200} defaultValue={state.draft?.name} />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input id="password" name="password" type="password" autoComplete="new-password" required minLength={PASSWORD_MIN} maxLength={256} />
              <span className="field-hint">At least {PASSWORD_MIN} characters. A passphrase of several words works well.</span>
            </div>
            <div className="field">
              <label htmlFor="password_confirm">Password again</label>
              <input id="password_confirm" name="password_confirm" type="password" autoComplete="new-password" required minLength={PASSWORD_MIN} maxLength={256} />
            </div>
            <button className="btn btn-primary btn-block" type="submit">
              Continue
            </button>
          </form>
        )}

        {state?.step === 'totp' && <TotpStep secret={state.totpSecret} email={state.email} issuer={appName} />}

        {state && (
          <form method="post" action="/setup/restart" className="auth-alt">
            <button className="link-btn" type="submit">
              Start over
            </button>
          </form>
        )}
      </div>
    </main>
  )
}

function TotpStep({ secret, email, issuer }: { secret: string; email: string; issuer: string }) {
  const uri = otpauthUri(secret, email, issuer)
  const { size, path } = qrPath(uri)
  return (
    <form className="form" method="post" action="/setup/totp">
      <p style={{ margin: 0 }}>
        Scan this code with an authenticator app (1Password, Google Authenticator, Microsoft Authenticator, …), then
        enter the six-digit code it shows.
      </p>
      <svg className="qr" viewBox={`-2 -2 ${size + 4} ${size + 4}`} role="img" aria-label="QR code for the authenticator app" shapeRendering="crispEdges">
        <path d={path} fill="#000" />
      </svg>
      <div className="field">
        <span className="field-hint">Or type this key into the app:</span>
        <div className="secret-box" data-testid="totp-secret">
          {secret.match(/.{1,4}/g)!.join(' ')}
        </div>
      </div>
      <div className="field">
        <label htmlFor="code">Code from the app</label>
        <input
          id="code"
          name="code"
          className="code-input"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9 ]{6,7}"
          maxLength={7}
          required
          autoFocus
        />
      </div>
      <button className="btn btn-primary btn-block" type="submit">
        Create owner account
      </button>
    </form>
  )
}

const fmtUtc = (iso: string) => `${iso.slice(0, 16).replace('T', ' ')} UTC`

// Where the operator finds the token, and a way to get a new one into the
// log when the line is gone (log retention, a missed container start).
function WhereIsTheToken({ status }: { status: SetupTokenStatus }) {
  if (status.source === 'environment') {
    return (
      <details className="disclosure" style={{ marginTop: '1rem' }} open>
        <summary>Where is the token?</summary>
        <p className="small" style={{ margin: 0 }}>
          This deployment sets it: it is the value of the <code>SETUP_TOKEN</code> environment variable.
        </p>
      </details>
    )
  }
  const onVercel = process.env.VERCEL === '1'
  return (
    <details className="disclosure" style={{ marginTop: '1rem' }} open>
      <summary>Where is the token?</summary>
      <p className="small" style={{ margin: 0 }}>
        It is written to the <strong>server log</strong>, never shown here, so that only someone who runs this server can create the
        owner. Search the log for <code>[setup]</code>
        {status.latestCreatedAt && (
          <>
            ; the newest was written at <strong>{fmtUtc(status.latestCreatedAt)}</strong>
            {status.latestExpiresAt && <> and works until {fmtUtc(status.latestExpiresAt)}</>}
          </>
        )}
        .
      </p>
      <ul className="small muted" style={{ margin: 0, paddingLeft: '1.1rem', display: 'grid', gap: '0.2rem' }}>
        {onVercel ? (
          <li>
            <strong>Vercel:</strong> your project → <em>Logs</em>, search <code>[setup]</code>. The Hobby plan keeps only an hour of logs:
            if the line is gone, write a new one below.
          </li>
        ) : (
          <>
            <li>
              <strong>Docker Compose:</strong> <code>docker compose logs web | grep setup</code>
            </li>
            <li>
              <strong>Kubernetes:</strong> <code>kubectl logs deploy/dmarcscope-web | grep setup</code>
            </li>
            <li>
              <strong>Vercel, Cloud Run and others:</strong> the platform&apos;s log viewer, searching <code>[setup]</code>
            </li>
          </>
        )}
      </ul>
      <form method="post" action="/setup/new-token" className="row" style={{ gap: '0.6rem' }}>
        <button className="btn btn-sm" type="submit">
          Write a new token to the log
        </button>
        <span className="small muted">Earlier tokens keep working.</span>
      </form>
      <p className="small muted" style={{ margin: 0 }}>
        Or choose one yourself: set <code>SETUP_TOKEN</code> (24 characters or more, e.g. <code>openssl rand -hex 16</code>) in the
        environment and restart or redeploy.
      </p>
    </details>
  )
}
