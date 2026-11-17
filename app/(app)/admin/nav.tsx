import Link from 'next/link'

const LINKS = [
  { href: '/admin', label: 'Settings' },
  { href: '/admin/users', label: 'Users' },
  { href: '/admin/rules', label: 'Access rules' },
  { href: '/admin/audit', label: 'Audit log' },
]

export function AdminNav({ current, pending = 0 }: { current: string; pending?: number }) {
  return (
    <nav className="seg admin-nav" aria-label="Administration" style={{ marginBottom: '1rem' }}>
      {LINKS.map((l) => (
        <Link key={l.href} href={l.href} aria-current={l.href === current ? 'true' : undefined}>
          {l.label}
          {l.href === '/admin/users' && pending > 0 && (
            <span className="count" aria-label={`${pending} pending requests`}>
              {pending}
            </span>
          )}
        </Link>
      ))}
    </nav>
  )
}
