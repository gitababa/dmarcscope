import Link from 'next/link'
import { cookies } from 'next/headers'
import { signOutAction } from '@/app/actions'
import { AppShell, SubmitButton, ThemeSwitch, type NavGroup } from '@/components/client'
import { Icon } from '@/components/icons'
import { Avatar, BrandMark } from '@/components/ui'
import { listPendingRequests } from '@/lib/admin'
import { listRules as listAlertRules } from '@/lib/alerts/admin'
import { authProvider, hasSignInPage } from '@/lib/auth'
import { atLeast } from '@/lib/auth/roles'
import { requireViewer } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { relTime } from '@/lib/format'
import { getDomainNames, getIngestHealth } from '@/lib/queries'
import { getAppName } from '@/lib/settings'

const SIDEBAR_DOMAINS = 8

// Every page under this layout needs a signed-in, authorized user. proxy.ts
// already enforces that; requireViewer() is the second, independent check.
export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const access = await requireViewer()
  const { session, role, domains: scope } = access
  const provider = authProvider()
  const isAdmin = atLeast(role, 'admin')
  const [name, domainNames, health, pending, openAlerts, theme] = await Promise.all([
    getAppName(),
    getDomainNames(scope).catch(() => [] as string[]),
    getIngestHealth(scope).catch(() => null),
    isAdmin ? listPendingRequests(access).then((p) => p.length).catch(() => 0) : 0,
    isAdmin
      ? listAlertRules(getPool())
          .then((rules) => rules.reduce((a, r) => a + (r.enabled ? r.open_events : 0), 0))
          .catch(() => 0)
      : 0,
    cookies().then((c) => c.get('theme')?.value),
  ])

  const groups: NavGroup[] = [
    {
      label: 'Monitor',
      items: [
        { href: '/', label: 'Overview', icon: 'overview' },
        {
          href: '/domains',
          label: 'Domains',
          icon: 'globe',
          match: ['/domains'],
          children: domainNames.slice(0, SIDEBAR_DOMAINS).map((d) => ({ href: `/domains/${encodeURIComponent(d)}`, label: d })),
        },
        { href: '/sources', label: 'Sources', icon: 'server', match: ['/sources'] },
        { href: '/issues', label: 'Issues', icon: 'alert', match: ['/issues'] },
      ],
    },
  ]
  if (isAdmin) {
    groups.push(
      {
        label: 'Data & alerting',
        items: [
          { href: '/admin/mail', label: 'Mailboxes', icon: 'inbox', match: ['/admin/mail'] },
          { href: '/admin/domains', label: 'Domains', icon: 'list' },
          { href: '/admin/alerts', label: 'Alerts', icon: 'bell', badge: openAlerts, badgeTone: 'bad' },
        ],
      },
      {
        label: 'Access',
        items: [
          { href: '/admin/users', label: 'People', icon: 'users', match: ['/admin/users'], badge: pending, badgeTone: 'warn' },
          { href: '/admin/rules', label: 'Access rules', icon: 'shield' },
          { href: '/admin/groups', label: 'Groups', icon: 'layers' },
          { href: '/admin/sso', label: 'Sign-in', icon: 'login', match: ['/admin/sso'] },
          { href: '/admin/api', label: 'API & SCIM', icon: 'key' },
        ],
      },
      {
        label: 'System',
        items: [
          { href: '/admin', label: 'Settings', icon: 'settings' },
          { href: '/admin/audit', label: 'Audit log', icon: 'scroll' },
        ],
      }
    )
  }

  const brand = (
    <Link href="/" className="sb-brand">
      <BrandMark />
      <span>
        {name}
        <small>DMARC monitoring</small>
      </span>
    </Link>
  )

  const ingestTone = !health || health.status === 'never' ? 'muted' : health.status === 'ok' ? (health.last_run_failed ? 'warn' : 'ok') : 'bad'
  const ingestText = !health
    ? 'Ingest status unknown'
    : health.status === 'never'
      ? 'No ingest run yet'
      : health.status === 'ok'
        ? `Ingest healthy · ${relTime(health.last_success_at)}`
        : `Ingest stale · ${health.last_success_at ? relTime(health.last_success_at) : 'never completed'}`

  const footer = (
    <>
      <Link href={isAdmin ? '/admin/mail' : '/'} className="row small" style={{ color: 'var(--text-muted)', gap: '0.5rem', padding: '0 0.25rem' }} title={ingestText}>
        <span className={`dot ${ingestTone}${ingestTone === 'ok' ? ' pulse' : ''}`} />
        {ingestText}
      </Link>
      <div className="sb-user">
        <Avatar name={provider === 'none' ? 'Anonymous' : session.identity.email} />
        <div className="sb-user-text">
          <div className="em" title={session.identity.email}>
            {provider === 'none' ? 'Sign-in disabled' : session.identity.email}
          </div>
          <div className="rl">{role}</div>
        </div>
        {hasSignInPage(provider) && (
          <form action={signOutAction}>
            <SubmitButton className="btn btn-ghost btn-icon">
              <Icon name="logout" size={17} />
              <span className="visually-hidden">Sign out</span>
            </SubmitButton>
          </form>
        )}
      </div>
      <ThemeSwitch initial={theme === 'light' || theme === 'dark' ? theme : 'system'} />
    </>
  )

  const banner =
    provider === 'none' ? (
      <div className="banner" role="note" title="AUTH_PROVIDER=none — anyone who can reach this app has full access">
        <Icon name="alert" size={14} /> Sign-in is disabled: anyone who can reach this app has full access.
      </div>
    ) : undefined

  return (
    <AppShell groups={groups} brand={brand} footer={footer} banner={banner}>
      {children}
      <footer className="footer" style={{ padding: '2.5rem 0 0' }}>
        <Icon name="lock" size={12} /> {name} is read-only: it never sends, blocks or changes mail.
      </footer>
    </AppShell>
  )
}
