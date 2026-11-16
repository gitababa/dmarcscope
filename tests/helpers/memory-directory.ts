// An in-memory Directory (lib/auth/directory.ts) for unit tests of the
// request gate. The database implementation is tested against PostgreSQL in
// tests/integration/.

import type { AuditEntry } from '@/lib/audit'
import type { Directory, UserRow, UserSource } from '@/lib/auth/directory'
import type { Identity, Role } from '@/lib/auth/types'
import type { AccessRule } from '@/lib/settings/store'

export class MemoryDirectory implements Directory {
  users: UserRow[] = []
  rules: AccessRule[] = []
  audits: AuditEntry[] = []
  ownerExists = true
  private nextId = 1

  add(row: Partial<UserRow> & { email: string; role: Role }): UserRow {
    const user: UserRow = {
      id: this.nextId++,
      name: null,
      role_source: 'assigned',
      status: 'active',
      source: 'local',
      sessions_valid_after: null,
      ...row,
    }
    this.users.push(user)
    return user
  }

  async config() {
    return { rules: this.rules, ownerExists: this.ownerExists }
  }
  async findById(id: number) {
    return this.users.find((u) => u.id === id) ?? null
  }
  async findByEmail(email: string) {
    return this.users.find((u) => u.email === email.toLowerCase()) ?? null
  }
  async admit(identity: Identity, role: Role, source: UserSource) {
    return (await this.findByEmail(identity.email)) ?? this.add({ email: identity.email.toLowerCase(), role, role_source: 'rule', source })
  }
  async requestAccess(identity: Identity, source: UserSource) {
    if (await this.findByEmail(identity.email)) return null
    return this.add({ email: identity.email.toLowerCase(), role: 'viewer', role_source: 'rule', status: 'pending', source })
  }
  async syncRuleRole(id: number, role: Role) {
    const u = this.users.find((x) => x.id === id)
    if (u && u.role_source === 'rule' && u.status !== 'disabled') {
      u.role = role
      u.status = 'active'
    }
  }
  async audit(entry: AuditEntry) {
    this.audits.push(entry)
  }
}
