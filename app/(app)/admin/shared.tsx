import { Notice } from '@/components/ui'
import type { Role } from '@/lib/auth/types'
import { atLeast } from '@/lib/auth/roles'

const ERRORS: Record<string, string> = {
  not_allowed: 'Only administrators can do that.',
  not_found: 'That no longer exists, or it changed meanwhile. This is the current state.',
  target_above_you: 'You cannot change someone whose role is above yours.',
  role_above_you: 'You cannot give a role above your own.',
  last_owner: 'That would leave no active owner. Make someone else an owner first.',
  self: 'You cannot disable or remove your own account.',
  not_pending: 'That is not a pending request any more. This is the current state.',
  exists: 'Someone with that address is already known. Find them in the list below.',
  invalid: 'That value is not valid. Check the address, domain or group name.',
  duplicate: 'That rule exists already.',
  not_applicable: 'Administrators and owners always see every domain, so a domain limit does not apply to them. Change the role first if that is what you want.',
  limit: 'There are too many active tokens. Revoke one first.',
}

const DONE: Record<string, string> = {
  invited: 'Invitation saved. The person gets access when they first sign in.',
  approved: 'Request approved. The person gets access on their next request.',
  rejected: 'Request rejected. The person stays refused; you can re-enable them later.',
  role: 'Role changed. It applies on the person’s next request.',
  disabled: 'Disabled. The person is refused from their next request on.',
  enabled: 'Enabled again.',
  signed_out: 'Every session of this person has been ended.',
  removed: 'Removed. Their history stays in the audit log.',
  added: 'Rule added. It applies within a few seconds on every instance.',
  deleted: 'Rule deleted. It stops applying within a few seconds on every instance.',
  scope_saved: 'Domain access saved. It applies on the person’s next request.',
  scope_cleared: 'The domain limit was removed. The groups and the default decide again.',
  revoked: 'Token revoked. It stops working at once.',
}

export function Notices({ error, done }: { error?: string; done?: string }) {
  return (
    <>
      {error && (
        <Notice tone="bad" role="alert">
          {ERRORS[error] ?? 'That could not be done.'}
        </Notice>
      )}
      {done && !error && DONE[done] && (
        <Notice tone="ok" role="status">
          {DONE[done]}
        </Notice>
      )}
    </>
  )
}

const ROLES: Role[] = ['viewer', 'admin', 'owner']

// The roles a caller may give: at or below their own.
export function RoleSelect({ actorRole, name = 'role', id, value, includeOwner = true, label }: {
  actorRole: Role
  name?: string
  id: string
  value?: string
  includeOwner?: boolean
  label: string
}) {
  return (
    <>
      <label htmlFor={id} className="visually-hidden">
        {label}
      </label>
      <select id={id} name={name} defaultValue={value ?? 'viewer'}>
        {ROLES.filter((r) => atLeast(actorRole, r) && (includeOwner || r !== 'owner')).map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
    </>
  )
}
