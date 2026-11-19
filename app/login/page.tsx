import type { Metadata } from 'next'
import Link from 'next/link'
import { Icon } from '@/components/icons'
import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { BrandMark, Notice } from '@/components/ui'
import { authProvider, hasSignInPage } from '@/lib/auth'
import { unsealMfaState } from '@/lib/auth/mfa-state'
import { getAuth } from '@/lib/auth/server'
import { purposeCookieName, safeReturnTo } from '@/lib/auth/session'
import { currentOidcSettings } from '@/lib/auth/connection'
import { configStore, getAppName, getSignInPolicy } from '@/lib/settings'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Sign in' }

const ERRORS: Record<string, string> = {
  expired: 'That sign-in attempt expired or was started in another browser. Please try again.',
  failed: 'Sign-in could not be completed. Please try again; if it keeps happening, contact your administrator.',
  no_email: 'Your identity provider did not share an email address, which this app needs to identify you.',
  unverified_email: 'Your identity provider did not confirm that your email address is verified.',
  wrong_account: 'That account does not belong to the organization this app is set up for. Sign in with your work account.',
  provider: 'The identity provider could not be reached. Please try again in a moment.',
  config: 'Sign-in is not configured correctly. An administrator needs to check the server configuration.',
  credentials: 'Email address or password is incorrect.',
  locked: 'Too many failed attempts. Wait a few minutes before trying again.',
  code: 'That code is not right, or it has already been used. Enter the current code from your authenticator app.',
}

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ returnTo?: string; error?: string; signed_out?: string; method?: string; step?: string }>
}) {
  const { returnTo: rawReturnTo, error, signed_out: signedOut, method, step } = await searchParams
  const returnTo = safeReturnTo(rawReturnTo)

  // With a proxy in front (or auth disabled) there is nothing to do here.
  const provider = authProvider()
  if (!hasSignInPage(provider)) redirect('/')
  const auth = await getAuth()
  if (auth.status === 'setup_required') redirect('/setup')
  if (auth.status === 'ok') redirect(returnTo)
  if (auth.status === 'forbidden') redirect('/denied')

  const appName = await getAppName()
  // Single sign-on: the environment's connection, or the one activated in
  // the panel. A broken one must not take the password sign-in down with it.
  const connection = await currentOidcSettings().catch((err) => {
    console.error('[auth] single sign-on connection unusable:', err instanceof Error ? err.message : String(err))
    return null
  })
  // The password sign-in: the only way in without single sign-on, and the
  // owner's way past single sign-on when that is broken.
  const passwordForm = !connection || method === 'password'
  const mfa = passwordForm && step === 'code' ? await unsealMfaState((await cookies()).get(purposeCookieName('mfa'))?.value) : null
  const ownerExists = connection && !passwordForm ? (await configStore().snapshot().catch(() => null))?.ownerExists : false
  const enforced = connection ? (await getSignInPolicy().catch(() => null))?.enforceSso : false

  const providerName = connection?.label
  const ssoHref = returnTo === '/' ? '/auth/login' : `/auth/login?returnTo=${encodeURIComponent(returnTo)}`
  const passwordHref = `/login?method=password${returnTo === '/' ? '' : `&returnTo=${encodeURIComponent(returnTo)}`}`

  return (
    <main className="auth-wrap">
      <div className="card auth-card">
        <BrandMark size={24} />
        <h1>{appName}</h1>
        <p>Sign in to monitor DMARC, SPF and DKIM for your sending domains.</p>
        {error && (
          <Notice tone="bad" role="alert">
            {ERRORS[error] ?? ERRORS.failed}
          </Notice>
        )}
        {signedOut && !error && <Notice tone="ok">You have been signed out.</Notice>}
        {passwordForm && step === 'code' && !mfa && !error && (
          <Notice tone="warn" role="status">
            That sign-in attempt expired. Enter your email address and password again.
          </Notice>
        )}

        {!passwordForm && (
          <>
            {/* A plain link (not a form) so the redirect to the identity provider
                is not subject to the form-action CSP directive. */}
            <a className="btn btn-primary btn-block" href={ssoHref}>
              {providerName ? `Sign in with ${providerName}` : 'Sign in with single sign-on'}
            </a>
            {ownerExists && (
              <div className="auth-alt">
                <Link href={passwordHref}>{enforced || provider === 'oidc' ? 'Owner sign-in with password' : 'Sign in with a password'}</Link>
              </div>
            )}
          </>
        )}

        {passwordForm && !mfa && (
          <form className="form" method="post" action="/auth/password">
            <input type="hidden" name="returnTo" value={returnTo} />
            <div className="field">
              <label htmlFor="email">Email address</label>
              <input id="email" name="email" type="email" autoComplete="username" required autoFocus maxLength={320} />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input id="password" name="password" type="password" autoComplete="current-password" required maxLength={1024} />
            </div>
            <button className="btn btn-primary btn-block" type="submit">
              Continue
            </button>
          </form>
        )}

        {passwordForm && mfa && (
          <form className="form" method="post" action="/auth/second-factor">
            <div className="field">
              <label htmlFor="code">Code from your authenticator app</label>
              <input id="code" name="code" className="code-input" autoComplete="one-time-code" required autoFocus maxLength={24} spellCheck={false} />
              <span className="field-hint">Lost your phone? Enter one of your recovery codes instead.</span>
            </div>
            <button className="btn btn-primary btn-block" type="submit">
              Sign in
            </button>
          </form>
        )}

        {passwordForm && connection && (
          <div className="auth-alt">
            <Link href={returnTo === '/' ? '/login' : `/login?returnTo=${encodeURIComponent(returnTo)}`}>Back to single sign-on</Link>
          </div>
        )}
        <div className="auth-foot">
          <Icon name="lock" size={12} /> Read-only monitoring: it never sends, blocks or changes mail.
        </div>
      </div>
    </main>
  )
}
