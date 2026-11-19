// Owner-only and admin-only actions refuse a caller with too low a role when
// called directly (a form post does not need the page that shows the form).

import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  role: null as null | 'viewer' | 'admin' | 'owner',
  writes: [] as Array<[string, unknown]>,
  audits: [] as Array<[string, Record<string, unknown>]>,
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
  notFound: () => {
    throw new Redirect('404')
  },
}))
vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }))
vi.mock('@/lib/auth/server', () => ({
  audit: async (action: string, detail: Record<string, unknown>) => {
    state.audits.push([action, detail])
  },
  currentActor: async () => ({ userId: 1, email: 'x@example.com', ip: null }),
  getAccessWithRole: async (minimum: string) => {
    const rank: Record<string, number> = { viewer: 1, admin: 2, owner: 3 }
    return state.role && rank[state.role] >= rank[minimum] ? { role: state.role, session: {}, domains: {} } : null
  },
}))
vi.mock('@/lib/settings', async (original) => ({
  ...(await original<typeof import('@/lib/settings')>()),
  configStore: () => ({
    write: async (key: string, value: unknown) => {
      state.writes.push([key, value])
    },
  }),
}))

import { updateSettingAction } from '@/app/(app)/admin/actions'

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

beforeEach(() => {
  state.writes.length = 0
  state.audits.length = 0
})

describe('updateSettingAction', () => {
  it('refuses an owner-only setting to admins and viewers, and records the refusal', async () => {
    for (const role of ['admin', 'viewer', null] as const) {
      state.role = role
      const to = await outcome(updateSettingAction(form({ key: 'cron.secret', value: 'x'.repeat(32) })))
      expect(to).toBe(role === 'admin' ? '/admin?error=owner_only' : '/denied')
    }
    for (const role of ['admin', 'viewer'] as const) {
      state.role = role
      await outcome(updateSettingAction(form({ key: 'session.max_age_hours', value: '24' })))
    }
    expect(state.writes).toEqual([])
    expect(state.audits.every(([a]) => a === 'action_refused')).toBe(true)
    expect(state.audits).toHaveLength(5)
  })

  it('refuses viewers everything and unknown settings to everyone', async () => {
    state.role = 'viewer'
    expect(await outcome(updateSettingAction(form({ key: 'app.name', value: 'X' })))).toBe('/denied')
    state.role = 'owner'
    expect(await outcome(updateSettingAction(form({ key: 'no.such', value: 'X' })))).toBe('/admin?error=unknown')
    expect(state.writes).toEqual([])
  })

  it('lets an admin change an ordinary setting and the owner a secret one', async () => {
    state.role = 'admin'
    expect(await outcome(updateSettingAction(form({ key: 'app.name', value: '  Mail Health ' })))).toBe('/admin?saved=app.name')
    state.role = 'owner'
    await outcome(updateSettingAction(form({ key: 'cron.secret', value: 'y'.repeat(32) })))
    // an empty secret field means "keep", not "clear"
    await outcome(updateSettingAction(form({ key: 'cron.secret', value: '' })))
    await outcome(updateSettingAction(form({ key: 'cron.secret', value: '', clear: '1' })))
    expect(state.writes).toEqual([
      ['app.name', 'Mail Health'],
      ['cron.secret', 'y'.repeat(32)],
      ['cron.secret', null],
    ])
  })
})

describe('admin reads', () => {
  it('refuse a viewer even if a page forgot to check', async () => {
    const { listAudit, listUsers, AdminAccessError } = await import('@/lib/admin')
    const viewer = { role: 'viewer', session: {}, domains: {} } as never
    await expect(listUsers(viewer)).rejects.toBeInstanceOf(AdminAccessError)
    await expect(listAudit(viewer)).rejects.toBeInstanceOf(AdminAccessError)
  })
})

describe('report queries', () => {
  it('all require a domain scope from the authorization function', async () => {
    const queries = await import('@/lib/queries')
    const fns = Object.entries(queries).filter(([, v]) => typeof v === 'function') as Array<[string, (...a: unknown[]) => Promise<unknown>]>
    expect(fns.length).toBeGreaterThanOrEqual(14)
    for (const [name, fn] of fns) {
      await expect(fn(undefined, 'example.com'), name).rejects.toThrow(/domain scope/)
      await expect(fn({ kind: 'all' }, 'example.com'), name).rejects.toThrow(/domain scope/)
    }
  })
})
