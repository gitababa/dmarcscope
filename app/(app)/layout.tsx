import Link from 'next/link'
import { signOutAction } from '@/app/actions'
import { NavTabs, SubmitButton } from '@/components/client'
import { Logo, Pill } from '@/components/ui'
import { authProvider } from '@/lib/auth'
import { requireViewer } from '@/lib/auth/server'
import { appName } from '@/lib/config'

// Every page under this layout needs a signed-in, authorized user. proxy.ts
// already enforces that; requireViewer() is the second, independent check.
export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await requireViewer()
  const provider = authProvider()
  const name = appName()

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <Link href="/" className="brand">
            <Logo />
            <span className="brand-name">{name}</span>
          </Link>
          <NavTabs />
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
              session.role === 'admin' && <Pill tone="info">admin</Pill>
            )}
            {provider === 'oidc' && (
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
