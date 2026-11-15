import type { Metadata } from 'next'
import { redirect } from 'next/navigation'
import { Logo } from '@/components/ui'
import { authProvider } from '@/lib/auth'
import { getAuth } from '@/lib/auth/server'
import { safeReturnTo } from '@/lib/auth/session'
import { appName } from '@/lib/config'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Sign in' }

const ERRORS: Record<string, string> = {
  expired: 'That sign-in attempt expired or was started in another browser. Please try again.',
  failed: 'Sign-in could not be completed. Please try again; if it keeps happening, contact your administrator.',
  no_email: 'Your identity provider did not share an email address, which this app needs to identify you.',
  unverified_email: 'Your identity provider reports that your email address is not verified.',
  provider: 'The identity provider could not be reached. Please try again in a moment.',
  config: 'Sign-in is not configured correctly. An administrator needs to check the server configuration.',
}

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ returnTo?: string; error?: string; signed_out?: string }>
}) {
  const { returnTo: rawReturnTo, error, signed_out: signedOut } = await searchParams
  const returnTo = safeReturnTo(rawReturnTo)

  // Only the built-in OIDC flow has a login page; with a proxy in front (or
  // auth disabled) there is nothing to do here.
  if (authProvider() !== 'oidc') redirect('/')
  const auth = await getAuth()
  if (auth.status === 'ok') redirect(returnTo)
  if (auth.status === 'forbidden') redirect('/denied')

  const providerName = process.env.OIDC_PROVIDER_NAME?.trim()
  const href = returnTo === '/' ? '/auth/login' : `/auth/login?returnTo=${encodeURIComponent(returnTo)}`

  return (
    <main className="auth-wrap">
      <div className="card auth-card">
        <Logo size={40} />
        <h1>{appName()}</h1>
        <p>DMARC, SPF and DKIM monitoring for your sending domains.</p>
        {error && (
          <div className="notice bad" role="alert">
            {ERRORS[error] ?? ERRORS.failed}
          </div>
        )}
        {signedOut && !error && <div className="notice ok">You have been signed out.</div>}
        {/* A plain link (not a form) so the redirect to the identity provider
            is not subject to the form-action CSP directive. */}
        <a className="btn btn-primary btn-block" href={href}>
          {providerName ? `Sign in with ${providerName}` : 'Sign in with single sign-on'}
        </a>
      </div>
    </main>
  )
}
