import type { Metadata } from 'next'
import Link from 'next/link'
import { SubmitButton } from '@/components/client'
import { Pill } from '@/components/ui'
import { listGroups } from '@/lib/access-admin'
import { requirePageRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { configStore } from '@/lib/settings'
import { clearGroupScopeAction, setGroupScopeAction } from '../access-actions'
import { AdminNav } from '../nav'
import { ScopeFields } from '../scope-fields'
import { Notices } from '../shared'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Groups' }

export default async function GroupsPage({ searchParams }: { searchParams: Promise<{ error?: string; done?: string; edit?: string }> }) {
  const access = await requirePageRole('admin')
  const { error, done, edit } = await searchParams
  const [groups, def] = await Promise.all([listGroups(getPool()), configStore().get('access.domain_default')])
  const fallback = def === 'none' ? 'none' : 'all'
  const anyLimited = groups.some((g) => g.scope?.mode === 'limited')
  const editing = groups.find((g) => g.name === edit) ?? null

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Groups</h1>
          <p>Limit people to chosen domains by group. A group is a name from your identity provider’s group claim or from SCIM.</p>
        </div>
      </div>
      <AdminNav current="/admin/groups" />
      <Notices error={error} done={done} />

      <section className="section" aria-labelledby="default-head">
        <div className="section-head">
          <h2 id="default-head">Viewers nobody has limited</h2>
        </div>
        <div className="card">
          <p className="small" style={{ margin: 0 }}>
            A viewer with no limit of their own and in no limited group sees <strong>{fallback === 'none' ? 'no domain' : 'every domain'}</strong>.
            Administrators and owners always see every domain.
          </p>
          {anyLimited && fallback === 'all' && (
            <div className="notice warn" role="note" style={{ marginTop: '0.8rem' }}>
              <span>
                Some groups are limited, but people in no group still see everything. If your identity provider ever stops sending groups,
                everyone would see everything. Set <strong>Domains a viewer sees without a scope</strong> to “none”
                {access.role === 'owner' ? (
                  <>
                    {' '}
                    in <Link href="/admin">Settings</Link>.
                  </>
                ) : (
                  <> (an owner can do this in Settings).</>
                )}
              </span>
            </div>
          )}
        </div>
      </section>

      <section className="section" aria-labelledby="groups-head">
        <div className="section-head">
          <h2 id="groups-head">Groups</h2>
        </div>
        <div className="card flush" role="list" aria-label="Groups">
          {groups.length === 0 && (
            <div className="person-row muted">No groups yet. A group appears here once an access rule names it, SCIM creates it, or you limit it below.</div>
          )}
          {groups.map((g) => (
            <div className="person-row" role="listitem" key={g.name}>
              <div className="person-who">
                <div className="source-name">
                  <Link href={`/admin/groups?edit=${encodeURIComponent(g.name)}#group-edit`} style={{ overflowWrap: 'anywhere' }}>
                    {g.name}
                  </Link>
                </div>
                <div className="source-meta">
                  {g.scope
                    ? g.scope.mode === 'all'
                      ? 'every domain'
                      : `${g.scope.domains.length} domain(s): ${g.scope.domains.slice(0, 3).join(', ')}${g.scope.domains.length > 3 ? '…' : ''}`
                    : 'no limit set'}
                  {g.from_scim ? ` · ${g.members} SCIM member(s)` : ''}
                  {g.in_rules ? ' · named by an access rule' : ''}
                </div>
              </div>
              <div className="person-tags">
                <Pill tone={g.scope?.mode === 'limited' ? 'info' : 'muted'}>{g.scope ? g.scope.mode : 'unset'}</Pill>
              </div>
            </div>
          ))}
        </div>

        <div id="group-edit" className="card" style={{ marginTop: '0.8rem' }}>
          <form action={setGroupScopeAction} className="form">
            <h3 style={{ marginTop: 0 }}>{editing ? `Domains for ${editing.name}` : 'Limit a group'}</h3>
            <div className="field">
              <label htmlFor="group">Group name</label>
              <input id="group" name="group" type="text" maxLength={300} required defaultValue={editing?.name ?? ''} />
            </div>
            <ScopeFields id="g" mode={editing?.scope?.mode ?? 'limited'} domains={editing?.scope?.domains ?? []} />
            <div className="inline-form">
              <SubmitButton className="btn btn-primary btn-sm" pendingLabel="Saving…">
                Save
              </SubmitButton>
            </div>
          </form>
          {editing?.scope && (
            <form action={clearGroupScopeAction} className="inline-form" style={{ marginTop: '0.8rem' }}>
              <input type="hidden" name="group" value={editing.name} />
              <SubmitButton className="btn btn-sm" pendingLabel="…">
                Remove this group’s limit
              </SubmitButton>
            </form>
          )}
        </div>
      </section>
    </>
  )
}
