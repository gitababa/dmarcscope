'use client'

// The only client-side JavaScript in the app: active-tab highlighting and a
// pending state for form buttons. Everything else is server-rendered.

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useFormStatus } from 'react-dom'
import type { ReactNode } from 'react'

const TABS = [
  { href: '/', label: 'Overview', match: (p: string) => p === '/' || p.startsWith('/domains') },
  { href: '/issues', label: 'Issues', match: (p: string) => p.startsWith('/issues') },
]
const ADMIN_TAB = { href: '/admin', label: 'Admin', match: (p: string) => p.startsWith('/admin') }

export function NavTabs({ admin = false }: { admin?: boolean }) {
  const pathname = usePathname() || '/'
  return (
    <nav className="nav" aria-label="Main">
      {(admin ? [...TABS, ADMIN_TAB] : TABS).map((t) => (
        <Link key={t.href} href={t.href} aria-current={t.match(pathname) ? 'page' : undefined}>
          {t.label}
        </Link>
      ))}
    </nav>
  )
}

export function SubmitButton({
  children,
  pendingLabel,
  className = 'btn',
}: {
  children: ReactNode
  pendingLabel?: string
  className?: string
}) {
  const { pending } = useFormStatus()
  return (
    <button type="submit" className={className} disabled={pending} aria-busy={pending}>
      {pending && pendingLabel ? pendingLabel : children}
    </button>
  )
}
