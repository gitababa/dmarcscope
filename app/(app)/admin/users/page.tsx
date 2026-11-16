import type { Metadata } from 'next'
import { Pill } from '@/components/ui'
import { listUsers } from '@/lib/admin'
import { requirePageRole } from '@/lib/auth/server'
import { relTime } from '@/lib/format'
import { AdminNav } from '../nav'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Users' }

const STATUS_TONE = { active: 'ok', pending: 'warn', disabled: 'bad' } as const

export default async function AdminUsersPage() {
  const access = await requirePageRole('admin')
  const users = await listUsers(access)

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <p>
            Everyone who has signed in or asked for access. A role from an access rule is worked out again on every
            request; managing users here arrives in a later release.
          </p>
        </div>
      </div>
      <AdminNav current="/admin/users" />
      <div className="card flush">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Person</th>
                <th>Role</th>
                <th>Status</th>
                <th>Sign-in</th>
                <th>Last sign-in</th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    No users yet.
                  </td>
                </tr>
              )}
              {users.map((u) => (
                <tr key={u.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <div className="source-name">{u.name || u.email}</div>
                    {u.name && <div className="source-meta">{u.email}</div>}
                  </td>
                  <td>
                    {u.role}
                    {u.role_source === 'rule' && <span className="muted small"> (from a rule)</span>}
                  </td>
                  <td>
                    <Pill tone={STATUS_TONE[u.status as keyof typeof STATUS_TONE] ?? 'muted'}>{u.status}</Pill>
                    {u.locked && (
                      <>
                        {' '}
                        <Pill tone="bad">locked</Pill>
                      </>
                    )}
                  </td>
                  <td>
                    {u.source}
                    {u.has_totp && <span className="muted small"> + TOTP</span>}
                  </td>
                  <td className="muted">{u.last_login_at ? relTime(u.last_login_at) : 'never'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
