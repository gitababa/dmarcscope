// The people and rules server actions, and the audit CSV export, called
// directly (a form post does not need the page that shows the form).

import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  role: null as null | 'viewer' | 'admin' | 'owner',
  calls: [] as Array<[string, unknown[]]>,
  audits: [] as Array<[string, Record<string, unknown>]>,
  refuse: null as null | string,
}))

class Redirect extends Error {
  constructor(public to: string) {
    super(`redirect:${to}`)
  }
}

vi.mock('next/navigation', () => ({
  redirect: (to: string) => {
    throw new Redirect(to)
  },
}))
vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }))
vi.mock('@/lib/db', () => ({ getPool: () => ({}) }))
vi.mock('@/lib/auth/server', () => ({
  audit: async (action: string, detail: Record<string, unknown>) => {
    state.audits.push([action, detail])
  },
  currentActor: async () => ({ userId: 1, email: 'me@example.com', ip: null }),
  getAccessWithRole: async (minimum: string) => {
    const rank: Record<string, number> = { viewer: 1, admin: 2, owner: 3 }
    return state.role && rank[state.role] >= rank[minimum] ? { role: state.role, session: { userId: 1 }, domains: {} } : null
  },
}))
vi.mock('@/lib/people', async (original) => {
  const real = await original<typeof import('@/lib/people')>()
  const fake = (name: string) => async (...args: unknown[]) => {
    // (pool, actor, ...arguments): keep the caller's role and the arguments
    state.calls.push([name, [(args[1] as { role: string }).role, ...args.slice(2)]])
    if (state.refuse) throw new real.Refusal(state.refuse as never)
  }
  return {
    ...real,
    inviteUser: fake('inviteUser'),
    approveRequest: fake('approveRequest'),
    rejectRequest: fake('rejectRequest'),
    changeRole: fake('changeRole'),
    setDisabled: fake('setDisabled'),
    signOutEverywhere: fake('signOutEverywhere'),
    removeUser: fake('removeUser'),
    addRule: fake('addRule'),
    deleteRule: fake('deleteRule'),
  }
})
vi.mock('@/lib/admin', async (original) => ({
  ...(await original<typeof import('@/lib/admin')>()),
  exportAudit: async () => [],
}))

import * as actions from '@/app/(app)/admin/people-actions'
import { GET as exportCsv } from '@/app/(app)/admin/audit/export/route'
import { NextRequest } from 'next/server'

const form = (fields: Record<string, string>) => {
  const f = new FormData()
  for (const [k, v] of Object.entries(fields)) f.set(k, v)
  return f
}
const outcome = async (p: Promise<void>) => {
  try {
    await p
  } catch (e) {
    if (e instanceof Redirect) return e.to
    throw e
  }
  return 'no redirect'
}

const ALL: Array<[keyof typeof actions, Record<string, string>]> = [
  ['inviteAction', { email: 'x@example.com', role: 'viewer' }],
  ['approveAction', { id: '5', role: 'viewer' }],
  ['rejectAction', { id: '5' }],
  ['changeRoleAction', { id: '5', role: 'viewer' }],
  ['disableAction', { id: '5' }],
  ['enableAction', { id: '5' }],
  ['signOutEverywhereAction', { id: '5' }],
  ['removeAction', { id: '5', confirm: 'yes' }],
  ['addRuleAction', { kind: 'group', value: 'staff', role: 'viewer' }],
  ['deleteRuleAction', { id: '5' }],
]

beforeEach(() => {
  state.calls.length = 0
  state.audits.length = 0
  state.refuse = null
})

describe('people actions', () => {
  it('refuse viewers and strangers before doing anything, and audit it', async () => {
    for (const role of ['viewer', null] as const) {
      state.role = role
      for (const [name, fields] of ALL) {
        expect(await outcome(actions[name](form(fields))), name).toBe('/denied')
      }
    }
    expect(state.calls).toEqual([])
    expect(state.audits).toHaveLength(ALL.length * 2)
    expect(state.audits.every(([a, d]) => a === 'action_refused' && d.reason === 'not_allowed')).toBe(true)
  })

  it('pass an admin through to the rules in lib/people.ts and report its refusals', async () => {
    state.role = 'admin'
    expect(await outcome(actions.changeRoleAction(form({ id: '7', role: 'admin', back: '/admin/users/7' })))).toBe('/admin/users/7?done=role')
    expect(state.calls).toEqual([['changeRole', ['admin', 7, 'admin']]])
    state.refuse = 'last_owner'
    expect(await outcome(actions.disableAction(form({ id: '7', back: '/admin/users/7' })))).toBe('/admin/users/7?error=last_owner')
  })

  it('only ever returns to a page of the admin area', async () => {
    state.role = 'admin'
    for (const back of ['https://evil.example/', '//evil.example', '/admin/../login', '/\\evil', 'javascript:alert(1)', '/adminx']) {
      expect(await outcome(actions.rejectAction(form({ id: '5', back }))), back).toBe('/admin/users?done=rejected')
    }
  })

  it('asks for confirmation before removing, and then goes back to the list', async () => {
    state.role = 'owner'
    expect(await outcome(actions.removeAction(form({ id: '5' })))).toBe('/admin/users/5?confirm=remove')
    expect(state.calls).toEqual([])
    expect(await outcome(actions.removeAction(form({ id: '5', confirm: 'yes', back: '/admin/users/5' })))).toBe('/admin/users?done=removed')
    expect(state.calls).toEqual([['removeUser', ['owner', 5]]])
  })
})

describe('audit CSV export', () => {
  it('is refused (as not found) to viewers and recorded', async () => {
    state.role = 'viewer'
    const res = await exportCsv(new NextRequest('http://localhost/admin/audit/export'))
    expect(res.status).toBe(404)
    expect(state.audits).toEqual([['action_refused', { action: 'audit_exported', reason: 'not_allowed' }]])
  })

  it('is an attachment for admins, and the export is recorded', async () => {
    state.role = 'admin'
    const res = await exportCsv(new NextRequest('http://localhost/admin/audit/export?action=sign_in'))
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('text/csv; charset=utf-8')
    expect(res.headers.get('content-disposition')).toMatch(/^attachment; filename="dmarcscope-audit-\d{4}-\d{2}-\d{2}\.csv"$/)
    expect(state.audits[0]).toMatchObject(['audit_exported', { rows: 0, filters: { action: 'sign_in' } }])
  })
})

describe('csvCell', async () => {
  const { csvCell } = await import('@/lib/admin')
  it('neutralizes formulas and quotes what needs quoting', () => {
    expect(csvCell('=1+1')).toBe("'=1+1")
    expect(csvCell('+cmd')).toBe("'+cmd")
    expect(csvCell('-2')).toBe("'-2")
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)")
    expect(csvCell('\tx')).toBe("'\tx")
    expect(csvCell('a,b')).toBe('"a,b"')
    expect(csvCell('say "hi"')).toBe('"say ""hi"""')
    expect(csvCell('line\nbreak')).toBe('"line\nbreak"')
    expect(csvCell(null)).toBe('')
    expect(csvCell({ k: 'v' })).toBe('"{""k"":""v""}"')
    expect(csvCell('plain')).toBe('plain')
  })
})
