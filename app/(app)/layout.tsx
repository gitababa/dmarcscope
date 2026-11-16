import Link from 'next/link'
import { signOutAction } from '@/app/actions'
import { NavTabs, SubmitButton } from '@/components/client'
import { Logo, Pill } from '@/components/ui'
import { authProvider, hasSignInPage } from '@/lib/auth'
import { atLeast } from '@/lib/auth/roles'
import { requireViewer } from '@/lib/auth/server'
import { getAppName } from '@/lib/settings'

// Every page under this layout needs a signed-in, authorized user. proxy.ts
// already enforces that; requireViewer() is the second, independent check.
export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const { session, role } = await requireViewer()
  const provider = authProvider()
  const name = await getAppName()

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <Link href="/" className="brand">
            <Logo />
            <span className="brand-name">{name}</span>
          </Link>
          <NavTabs admin={atLeast(role, 'admin')} />
          <div className="userbox">
            {provider !== 'none' && (
              <span className="email" title={session.identity.email}>
                {session.identity.email}
              </span>
            )}
            {provider === 'none' ? (
              <Pill tone="warn" title="AUTH_PROVIDER=none — anyone who can reach this app has full access">
                auth disabled
              </Pill>
            ) : (
              atLeast(role, 'admin') && <Pill tone="info">{role}</Pill>
            )}
            {hasSignInPage(provider) && (
              <form action={signOutAction}>
                <SubmitButton className="btn btn-sm">Sign out</SubmitButton>
              </form>
            )}
          </div>
        </div>
      </header>
      <main className="container">{children}</main>
      <footer className="footer">{name} · read-only monitoring; it never sends, blocks or changes mail</footer>
    </>
  )
}
