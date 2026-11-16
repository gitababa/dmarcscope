import type { Role } from './types'

const RANK: Record<Role, number> = { viewer: 1, admin: 2, owner: 3 }

export function atLeast(role: Role | null | undefined, minimum: Role): boolean {
  return role != null && RANK[role] >= RANK[minimum]
}

export function higherRole(a: Role | null, b: Role | null): Role | null {
  if (!a) return b
  if (!b) return a
  return RANK[a] >= RANK[b] ? a : b
}

export function isRole(v: unknown): v is Role {
  return v === 'owner' || v === 'admin' || v === 'viewer'
}
