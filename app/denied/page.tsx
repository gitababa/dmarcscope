import type { Metadata } from 'next'
import { redirect } from 'next/navigation'
import { signOutAction } from '@/app/actions'
import { SubmitButton } from '@/components/client'
import { Logo } from '@/components/ui'
import { authProvider, hasSignInPage } from '@/lib/auth'
import { getAuth } from '@/lib/auth/server'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Access not granted' }

export default async function DeniedPage() {
  const provider = authProvider()
  const auth = await getAuth()
  if (auth.status === 'ok') redirect('/')
  if (auth.status === 'setup_required') redirect('/setup')
  if (auth.status === 'unauthenticated' && hasSignInPage(provider)) redirect('/login')

  return (
    <main className="auth-wrap">
      <div className="card auth-card">
        <Logo size={40} />
        {auth.status === 'forbidden' ? (
          <>
            <h1>Access not granted</h1>
            <p>
              You are signed in as <strong>{auth.identity.email}</strong>, but this account has not been given access
              to this dashboard. Your request has been recorded; ask an administrator to let you in, then reload this
              page.
            </p>
            {hasSignInPage(provider) && (
              <form action={signOutAction}>
                <SubmitButton className="btn btn-block">Sign out</SubmitButton>
              </form>
            )}
          </>
        ) : (
          <>
            <h1>Not signed in</h1>
            <p>
              This dashboard is protected by an access proxy, and this request arrived without a valid identity from
              it. Open the dashboard through its official address; if you already did, contact your administrator.
            </p>
          </>
        )}
      </div>
    </main>
  )
}
