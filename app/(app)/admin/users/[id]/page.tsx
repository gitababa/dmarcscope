import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { SubmitButton } from '@/components/client'
import { Pill } from '@/components/ui'
import { getUser } from '@/lib/admin'
import { atLeast } from '@/lib/auth/roles'
import { requirePageRole } from '@/lib/auth/server'
import type { Role } from '@/lib/auth/types'
import { fmtDate, relTime } from '@/lib/format'
import { AdminNav } from '../../nav'
import { changeRoleAction, disableAction, enableAction, removeAction, signOutEverywhereAction } from '../../people-actions'
import { Notices, RoleSelect } from '../../shared'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'User' }

export default async function AdminUserPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>
  searchParams: Promise<{ error?: string; done?: string; confirm?: string }>
}) {
  const access = await requirePageRole('admin')
  const [{ id: rawId }, { error, done, confirm }] = await Promise.all([params, searchParams])
  const user = await getUser(access, Number(rawId))
  if (!user) notFound()

  const self = access.session.userId === user.id
  // Only the actions the caller may take are shown; the server checks again.
  const mayChange = atLeast(access.role, user.role as Role)
  const back = `/admin/users/${user.id}`
  const hidden = (
    <>
      <input type="hidden" name="id" value={user.id} />
      <input type="hidden" name="back" value={back} />
    </>
  )

  return (
    <>
      <Link href="/admin/users" className="crumb">
        ← All users
      </Link>
      <div className="page-head">
        <div>
          <h1 style={{ overflowWrap: 'anywhere' }}>{user.name || user.email}</h1>
          <p>
            {user.name ? `${user.email} · ` : ''}
            {self ? 'this is you' : `signs in via ${user.source}`}
          </p>
        </div>
      </div>
      <AdminNav current="/admin/users" />
      <Notices error={error} done={done} />

      <div className="card">
        <dl className="kv-list">
          <dt>Role</dt>
          <dd>
            <Pill tone={user.role === 'viewer' ? 'muted' : 'info'}>{user.role}</Pill>{' '}
            <span className="muted small">{user.role_source === 'rule' ? 'from an access rule (re-evaluated on every request)' : 'assigned'}</span>
          </dd>
          <dt>Status</dt>
          <dd>
            {user.status === 'pending' && user.invited ? 'invited, has not signed in yet' : user.status}
            {user.locked && (
              <>
                {' '}
                <Pill tone="bad">locked until {user.locked_until ? new Date(user.locked_until).toISOString().slice(11, 16) : '?'} UTC</Pill>
              </>
            )}
          </dd>
          <dt>Sign-in</dt>
          <dd>
            {user.source}
            {user.has_totp ? ' with password and TOTP' : ''}
          </dd>
          <dt>Last sign-in</dt>
          <dd>{user.last_login_at ? `${relTime(user.last_login_at)} (${fmtDate(user.last_login_at)})` : 'never'}</dd>
          {user.invited_at && (
            <>
              <dt>Invited</dt>
              <dd>
                {fmtDate(user.invited_at)}
                {user.invited_by_email ? ` by ${user.invited_by_email}` : ''}
              </dd>
            </>
          )}
          {user.sessions_valid_after && (
            <>
              <dt>Signed out everywhere</dt>
              <dd>{relTime(user.sessions_valid_after)}</dd>
            </>
          )}
          <dt>Known since</dt>
          <dd>{fmtDate(user.created_at)}</dd>
        </dl>
      </div>

      {!mayChange && (
        <div className="notice" role="note">
          This person’s role is above yours, so you cannot change anything here.
        </div>
      )}

      {mayChange && (
        <section className="section" aria-labelledby="actions-head">
          <div className="section-head">
            <h2 id="actions-head">Change</h2>
          </div>
          <div className="card actions-card">
            <form action={changeRoleAction} className="inline-form">
              {hidden}
              <RoleSelect actorRole={access.role} id="role" value={user.role} label="New role" />
              <SubmitButton className="btn btn-sm">Change role</SubmitButton>
            </form>

            <form action={signOutEverywhereAction} className="inline-form">
              {hidden}
              <SubmitButton className="btn btn-sm">Sign out everywhere</SubmitButton>
              <span className="muted small">Ends every session; they can sign in again.</span>
            </form>

            {!self && user.status !== 'disabled' && (
              <form action={disableAction} className="inline-form">
                {hidden}
                <SubmitButton className="btn btn-sm">Disable</SubmitButton>
                <span className="muted small">Refused from their next request until re-enabled.</span>
              </form>
            )}
            {user.status === 'disabled' && (
              <form action={enableAction} className="inline-form">
                {hidden}
                <SubmitButton className="btn btn-sm">Enable</SubmitButton>
              </form>
            )}

            {!self &&
              (confirm === 'remove' ? (
                <form action={removeAction} className="notice bad confirm" role="alert">
                  {hidden}
                  <input type="hidden" name="confirm" value="yes" />
                  <span>
                    Remove <strong>{user.email}</strong>? Their history stays in the audit log. If an access rule admits them,
                    they come back as a new user at their next sign-in; disable them instead to keep them out.
                  </span>
                  <span className="inline-form">
                    <SubmitButton className="btn btn-sm">Yes, remove</SubmitButton>
                    <Link href={back} className="small">
                      Cancel
                    </Link>
                  </span>
                </form>
              ) : (
                <form action={removeAction} className="inline-form">
                  {hidden}
                  <SubmitButton className="btn btn-sm">Remove…</SubmitButton>
                </form>
              ))}
          </div>
        </section>
      )}
    </>
  )
}
