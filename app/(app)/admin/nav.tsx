import Link from 'next/link'

const LINKS = [
  { href: '/admin', label: 'Settings' },
  { href: '/admin/users', label: 'Users' },
  { href: '/admin/audit', label: 'Audit log' },
]

export function AdminNav({ current }: { current: string }) {
  return (
    <nav className="seg" aria-label="Administration" style={{ marginBottom: '1rem' }}>
      {LINKS.map((l) => (
        <Link key={l.href} href={l.href} aria-current={l.href === current ? 'true' : undefined}>
          {l.label}
        </Link>
      ))}
    </nav>
  )
}
