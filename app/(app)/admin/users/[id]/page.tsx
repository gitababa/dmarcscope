import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { FocusedSubmitButton, SubmitButton } from '@/components/client'
import { Avatar, Card, Notice, PageHeader, Pill } from '@/components/ui'
import { getUserScope, listUserGroups } from '@/lib/access-admin'
import { getUser } from '@/lib/admin'
import { atLeast } from '@/lib/auth/roles'
import { requirePageRole } from '@/lib/auth/server'
import type { Role } from '@/lib/auth/types'
import { getPool } from '@/lib/db'
import { fmtDate, relTime } from '@/lib/format'
import { clearUserScopeAction, setUserScopeAction } from '../../access-actions'
import { changeRoleAction, disableAction, enableAction, removeAction, signOutEverywhereAction } from '../../people-actions'
import { ScopeFields } from '../../scope-fields'
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

  const [scope, groups] = await Promise.all([getUserScope(getPool(), user.id), listUserGroups(getPool(), user.id)])
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
      <PageHeader
        crumbs={[{ href: '/admin/users', label: 'People' }, { label: user.name || user.email }]}
        title={
          <span className="row" style={{ gap: '0.8rem' }}>
            <Avatar name={user.name || user.email} large />
            {user.name || user.email}
          </span>
        }
        badge={
          <>
            <Pill tone={user.role === 'viewer' ? 'muted' : 'info'}>{user.role}</Pill>
            <Pill tone={user.status === 'active' ? 'ok' : user.status === 'pending' ? 'warn' : 'bad'} dot>
              {user.status === 'pending' && user.invited ? 'invited' : user.status}
            </Pill>
          </>
        }
        lead={
          <>
            {user.name ? `${user.email} · ` : ''}
            {self ? 'this is you' : `signs in via ${user.source}`}
          </>
        }
      />
      <Notices error={error} done={done} />

      <div className="grid-main-side">
      <div>
      <Card title="Profile" icon="users">
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
      </Card>

      <section className="section" aria-labelledby="scope-head">
        {user.role !== 'viewer' ? (
          <div className="card">
            <div className="card-head">
              <h2 id="scope-head">Domain access</h2>
            </div>
            <p className="small" style={{ margin: 0 }}>
              {user.role === 'owner' ? 'Owners' : 'Administrators'} always see every domain. A domain limit only applies to viewers. If you make a limited viewer an
              administrator, the limit stops applying.
            </p>
          </div>
        ) : (
          <div className="card">
            <div className="card-head">
              <h2 id="scope-head">Domain access</h2>
            </div>
            <p className="small" style={{ marginTop: 0 }}>
              {scope
                ? scope.mode === 'all'
                  ? 'This person is set to see every domain.'
                  : `This person is limited to ${scope.domains.length} domain(s)${scope.domains.length === 0 ? ', so they see nothing' : ''}.`
                : 'No limit is set for this person. Their groups and the default decide.'}
              {groups.length > 0 && (
                <>
                  {' '}
                  Groups (SCIM):{' '}
                  {groups.map((g) => `${g.name}${g.scope ? ` (${g.scope.mode === 'all' ? 'every domain' : `${g.scope.domains.length} domain(s)`})` : ''}`).join(', ')}.
                </>
              )}
            </p>
            <form action={setUserScopeAction} className="form">
              <input type="hidden" name="id" value={user.id} />
              <ScopeFields id="u" mode={scope?.mode ?? 'limited'} domains={scope?.domains ?? []} />
              <div className="inline-form">
                <SubmitButton className="btn btn-primary btn-sm" pendingLabel="Saving…">
                  Save domain access
                </SubmitButton>
              </div>
            </form>
            {scope && (
              <form action={clearUserScopeAction} className="inline-form" style={{ marginTop: '0.8rem' }}>
                <input type="hidden" name="id" value={user.id} />
                <SubmitButton className="btn btn-sm" pendingLabel="…">
                  Remove this person’s own setting
                </SubmitButton>
              </form>
            )}
          </div>
        )}
      </section>

      </div>
      <div>
      {!mayChange && (
        <Notice tone="info" role="note">
          This person’s role is above yours, so you cannot change anything here.
        </Notice>
      )}

      {mayChange && (
        <section aria-labelledby="actions-head">
          <div className="card actions-card" style={{ display: 'grid', gap: '1rem' }}>
            <div className="card-head">
              <h2 id="actions-head">Actions</h2>
            </div>
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
                <form action={removeAction} className="notice bad confirm" role="alert" style={{ marginBottom: 0 }}>
                  {hidden}
                  <input type="hidden" name="confirm" value="yes" />
                  <span>
                    Remove <strong>{user.email}</strong>? Their history stays in the audit log. If an access rule admits them,
                    they come back as a new user at their next sign-in; disable them instead to keep them out.
                  </span>
                  <span className="inline-form">
                    {/* Focus goes straight to the decision, for keyboard users. */}
                    <FocusedSubmitButton className="btn btn-sm">Yes, remove</FocusedSubmitButton>
                    <Link href={back} className="small">
                      Cancel
                    </Link>
                  </span>
                </form>
              ) : (
                <form action={removeAction} className="inline-form">
                  {hidden}
                  <SubmitButton className="btn btn-sm btn-danger-ghost">Remove…</SubmitButton>
                </form>
              ))}
          </div>
        </section>
      )}
      </div>
      </div>
    </>
  )
}
