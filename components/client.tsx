'use client'

// The client-side JavaScript in the app: the sidebar (active link, mobile
// drawer), the theme switch, a pending state for form buttons, moving focus
// to a confirmation, and refreshing a page while it waits for the worker.
// Everything else is server-rendered.

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { useFormStatus } from 'react-dom'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Icon, type IconName } from './icons'

export type NavItem = {
  href: string
  label: string
  icon: IconName
  // Paths that count as this item (prefix match); the href itself matches exactly.
  match?: string[]
  badge?: number
  badgeTone?: 'bad' | 'warn'
  children?: Array<{ href: string; label: string }>
}
export type NavGroup = { label: string; items: NavItem[] }

function isActive(item: NavItem, path: string): boolean {
  if (path === item.href) return true
  return (item.match ?? []).some((m) => path === m || path.startsWith(m.endsWith('/') ? m : `${m}/`))
}

export function AppShell({
  groups,
  brand,
  footer,
  banner,
  children,
}: {
  groups: NavGroup[]
  brand: ReactNode
  footer: ReactNode
  banner?: ReactNode
  children: ReactNode
}) {
  const path = usePathname() || '/'
  const [open, setOpen] = useState(false)
  // Close the drawer on navigation.
  useEffect(() => setOpen(false), [path])
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  return (
    <div className="app" data-nav={open ? 'open' : 'closed'}>
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <aside className="sidebar" aria-label="Sidebar">
        <div className="row" style={{ paddingRight: '0.7rem' }}>
          {brand}
          <button type="button" className="btn btn-ghost btn-icon sb-close" onClick={() => setOpen(false)} aria-label="Close menu">
            <Icon name="x" size={18} />
          </button>
        </div>
        <nav className="sb-scroll" aria-label="Main">
          {groups.map((g) => (
            <div className="sb-section" key={g.label}>
              <div className="sb-label">{g.label}</div>
              {g.items.map((item) => {
                const active = isActive(item, path)
                return (
                  <div key={item.href}>
                    <Link href={item.href} className="sb-link" aria-current={active ? 'page' : undefined}>
                      <Icon name={item.icon} size={17} />
                      <span>{item.label}</span>
                      {item.badge ? (
                        <span className={`sb-badge${item.badgeTone ? ` ${item.badgeTone}` : ''}`} aria-label={`${item.badge} need attention`}>
                          {item.badge > 99 ? '99+' : item.badge}
                        </span>
                      ) : null}
                    </Link>
                    {item.children && item.children.length > 0 && (
                      <div className="sb-sub">
                        {item.children.map((c) => (
                          <Link key={c.href} href={c.href} aria-current={path === c.href.split('?')[0] ? 'page' : undefined} title={c.label}>
                            <span className="nm">{c.label}</span>
                          </Link>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ))}
        </nav>
        <div className="sb-foot">{footer}</div>
      </aside>
      <button type="button" className="scrim" aria-label="Close menu" tabIndex={-1} onClick={() => setOpen(false)} />
      <div className="main">
        {banner}
        <div className="mobile-bar">
          <button type="button" className="btn btn-ghost btn-icon" onClick={() => setOpen(true)} aria-label="Open menu" aria-expanded={open}>
            <Icon name="menu" size={20} />
          </button>
          {brand}
        </div>
        <main id="main" className="content">
          {children}
        </main>
      </div>
    </div>
  )
}

type Theme = 'system' | 'light' | 'dark'
const THEMES: Array<{ value: Theme; label: string; icon: IconName }> = [
  { value: 'system', label: 'Auto', icon: 'monitor' },
  { value: 'light', label: 'Light', icon: 'sun' },
  { value: 'dark', label: 'Dark', icon: 'moon' },
]

// The choice lives in a cookie so the server renders the right theme on the
// first paint (no flash), and on <html data-theme> for this page.
export function ThemeSwitch({ initial }: { initial: Theme }) {
  const [theme, setTheme] = useState<Theme>(initial)
  const choose = (t: Theme) => {
    setTheme(t)
    const root = document.documentElement
    if (t === 'system') delete root.dataset.theme
    else root.dataset.theme = t
    document.cookie = `theme=${t}; path=/; max-age=${60 * 60 * 24 * 365}; samesite=lax`
  }
  return (
    <div className="theme-switch" role="group" aria-label="Colour theme">
      {THEMES.map((t) => (
        <button key={t.value} type="button" aria-pressed={theme === t.value} onClick={() => choose(t.value)} title={`${t.label} theme`}>
          <Icon name={t.icon} size={13} />
          {t.label}
        </button>
      ))}
    </div>
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
