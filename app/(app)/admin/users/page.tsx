import type { Metadata } from 'next'
import Link from 'next/link'
import { SubmitButton } from '@/components/client'
import { Pill } from '@/components/ui'
import { USERS_PAGE, listPendingRequests, listUsers, parseUserFilters } from '@/lib/admin'
import { requirePageRole } from '@/lib/auth/server'
import { relTime } from '@/lib/format'
import { AdminNav } from '../nav'
import { approveAction, inviteAction, rejectAction } from '../people-actions'
import { Notices, RoleSelect } from '../shared'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Users' }

const STATUS_TONE = { active: 'ok', pending: 'warn', disabled: 'bad' } as const

type Search = { q?: string; status?: string; role?: string; source?: string; page?: string; error?: string; done?: string }

export default async function AdminUsersPage({ searchParams }: { searchParams: Promise<Search> }) {
  const access = await requirePageRole('admin')
  const params = await searchParams
  const filters = parseUserFilters(params)
  const [{ rows: users, total }, pending] = await Promise.all([listUsers(access, filters), listPendingRequests(access)])
  const page = filters.page ?? 1
  const pages = Math.max(1, Math.ceil(total / USERS_PAGE))
  const pageHref = (n: number) => {
    const q = new URLSearchParams()
    for (const k of ['q', 'status', 'role', 'source'] as const) if (filters[k]) q.set(k, String(filters[k]))
    if (n > 1) q.set('page', String(n))
    return `/admin/users${q.size ? `?${q}` : ''}`
  }
  const filtered = Boolean(filters.q || filters.status || filters.role || filters.source)

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <p>Everyone who has signed in, been invited or asked for access. Changes apply on the person’s next request.</p>
        </div>
      </div>
      <AdminNav current="/admin/users" pending={pending.length} />
      <Notices error={params.error} done={params.done} />

      {pending.length > 0 && (
        <section className="section" aria-labelledby="pending-head">
          <div className="section-head">
            <h2 id="pending-head">Waiting for approval ({pending.length})</h2>
          </div>
          <div className="card flush" role="list" aria-label="Pending requests">
            {pending.map((u) => (
              <div className="person-row" role="listitem" key={u.id}>
                <div className="person-who">
                  <div className="source-name">{u.name || u.email}</div>
                  <div className="source-meta">
                    {u.name ? `${u.email} · ` : ''}asked {relTime(u.created_at)} · {u.source}
                  </div>
                </div>
                <form action={approveAction} className="inline-form">
                  <input type="hidden" name="id" value={u.id} />
                  <input type="hidden" name="back" value="/admin/users" />
                  <RoleSelect actorRole={access.role} id={`approve-role-${u.id}`} label={`Role for ${u.email}`} />
                  <SubmitButton className="btn btn-sm btn-primary">Approve</SubmitButton>
                </form>
                <form action={rejectAction}>
                  <input type="hidden" name="id" value={u.id} />
                  <input type="hidden" name="back" value="/admin/users" />
                  <SubmitButton className="btn btn-sm">Reject</SubmitButton>
                </form>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="section" aria-labelledby="people-head">
        <div className="section-head">
          <h2 id="people-head">People {filtered ? `(${total} found)` : `(${total})`}</h2>
        </div>
        <form method="get" action="/admin/users" className="filters" role="search" aria-label="Find people">
          <label htmlFor="q" className="visually-hidden">
            Search by address or name
          </label>
          <input id="q" name="q" type="search" placeholder="Address or name" defaultValue={filters.q} maxLength={200} />
          <Filter name="status" label="Status" value={filters.status} options={['pending', 'active', 'disabled']} />
          <Filter name="role" label="Role" value={filters.role} options={['owner', 'admin', 'viewer']} />
          <Filter name="source" label="Sign-in" value={filters.source} options={['local', 'oidc', 'proxy']} />
          <button className="btn btn-sm" type="submit">
            Filter
          </button>
          {filtered && (
            <Link href="/admin/users" className="small">
              Clear
            </Link>
          )}
        </form>

        <div className="card flush" role="list" aria-label="People">
          {users.length === 0 && <div className="person-row muted">{filtered ? 'Nobody matches.' : 'No users yet.'}</div>}
          {users.map((u) => (
            <div className="person-row" role="listitem" key={u.id}>
              <div className="person-who">
                <Link href={`/admin/users/${u.id}`} className="source-name">
                  {u.name || u.email}
                </Link>
                <div className="source-meta">
                  {u.name ? `${u.email} · ` : ''}
                  {u.source}
                  {u.has_totp ? ' + TOTP' : ''} · last sign-in {u.last_login_at ? relTime(u.last_login_at) : 'never'}
                </div>
              </div>
              <div className="person-tags">
                <Pill tone={u.role === 'viewer' ? 'muted' : 'info'}>{u.role}</Pill>
                {u.role_source === 'rule' && <span className="muted small">from a rule</span>}
                <Pill tone={STATUS_TONE[u.status as keyof typeof STATUS_TONE] ?? 'muted'}>
                  {u.status === 'pending' && u.invited ? 'invited' : u.status}
                </Pill>
                {u.locked && <Pill tone="bad">locked</Pill>}
              </div>
            </div>
          ))}
        </div>
        {pages > 1 && (
          <nav className="pager" aria-label="Pages">
            {page > 1 ? <Link href={pageHref(page - 1)}>← Previous</Link> : <span />}
            <span className="muted small">
              Page {page} of {pages}
            </span>
            {page < pages ? <Link href={pageHref(page + 1)}>Next →</Link> : <span />}
          </nav>
        )}
      </section>

      <section className="section" aria-labelledby="invite-head">
        <div className="section-head">
          <h2 id="invite-head">Invite someone</h2>
        </div>
        <div className="card">
          <p className="muted small" style={{ marginTop: 0 }}>
            Gives an address a role before the person first signs in (through single sign-on or your access proxy). No
            email is sent: tell them where to sign in.
          </p>
          <form action={inviteAction} className="inline-form">
            <input type="hidden" name="back" value="/admin/users" />
            <label htmlFor="invite-email" className="visually-hidden">
              Email address to invite
            </label>
            <input id="invite-email" name="email" type="email" required maxLength={254} placeholder="name@example.com" className="grow" />
            <RoleSelect actorRole={access.role} id="invite-role" label="Role for the invited person" />
            <SubmitButton className="btn btn-primary btn-sm">Invite</SubmitButton>
          </form>
        </div>
      </section>
    </>
  )
}

function Filter({ name, label, value, options }: { name: string; label: string; value?: string; options: string[] }) {
  return (
    <>
      <label htmlFor={`f-${name}`} className="visually-hidden">
        {label}
      </label>
      <select id={`f-${name}`} name={name} defaultValue={value ?? ''}>
        <option value="">{label}: any</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {label}: {o}
          </option>
        ))}
      </select>
    </>
  )
}
