'use client'

// The only client-side JavaScript in the app: active-tab highlighting, a
// pending state for form buttons, moving focus to a confirmation, and
// refreshing a page while it waits for the worker.
// Everything else is server-rendered.

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { useFormStatus } from 'react-dom'
import { useEffect, useRef, type ReactNode } from 'react'

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

// A submit button that takes keyboard focus when it appears (a confirmation
// step), so keyboard users land on the decision. React does not apply
// autoFocus to server-rendered HTML, hence the effect.
export function FocusedSubmitButton({ children, className = 'btn' }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLButtonElement>(null)
  useEffect(() => ref.current?.focus(), [])
  return (
    <button ref={ref} type="submit" className={className}>
      {children}
    </button>
  )
}

// Re-renders the server page every few seconds while `active` (a job waiting
// for the worker), and stops after a few minutes so a forgotten tab does not
// poll forever.
export function AutoRefresh({ active, seconds = 3, maxMinutes = 5 }: { active: boolean; seconds?: number; maxMinutes?: number }) {
  const router = useRouter()
  useEffect(() => {
    if (!active) return
    const started = Date.now()
    const timer = setInterval(() => {
      if (Date.now() - started > maxMinutes * 60_000) clearInterval(timer)
      else router.refresh()
    }, seconds * 1000)
    return () => clearInterval(timer)
  }, [active, seconds, maxMinutes, router])
  return null
}
