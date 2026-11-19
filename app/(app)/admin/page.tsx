import type { Metadata } from 'next'
import { SubmitButton } from '@/components/client'
import type { IconName } from '@/components/icons'
import { Card, Notice, PageHeader, Pill } from '@/components/ui'
import { atLeast } from '@/lib/auth/roles'
import { requirePageRole } from '@/lib/auth/server'
import { REGISTRY, type ResolvedSetting, configStore } from '@/lib/settings'
import { updateSettingAction } from './actions'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Settings' }

const ERRORS: Record<string, string> = {
  owner_only: 'Only the owner can change that setting.',
  unknown: 'There is no such setting.',
  managed_by_environment: 'That setting is managed by an environment variable and cannot be changed here.',
  invalid: 'That value is not valid.',
}

// Settings shown together, by the first part of their key.
const GROUPS: Array<{ title: string; icon: IconName; sub: string; prefixes: string[] }> = [
  { title: 'General', icon: 'settings', sub: 'Name and sessions', prefixes: ['app', 'session'] },
  { title: 'Data & retention', icon: 'inbox', sub: 'How long reports are kept and when ingest counts as stale', prefixes: ['ingest'] },
  { title: 'Sign-in & access', icon: 'shield', sub: 'Password sign-in, single sign-on and what unscoped viewers see', prefixes: ['auth', 'access'] },
  { title: 'Email delivery', icon: 'mail', sub: 'The SMTP server alert emails are sent through', prefixes: ['smtp'] },
  { title: 'Alerts & automation', icon: 'bell', sub: 'Webhook safety and the token for machine endpoints', prefixes: ['alerts', 'cron'] },
]

const SOURCE_LABEL: Record<ResolvedSetting['source'], string> = {
  environment: 'managed by environment',
  database: 'set here',
  default: 'default',
}

export default async function AdminSettingsPage({ searchParams }: { searchParams: Promise<{ error?: string; saved?: string; key?: string }> }) {
  const access = await requirePageRole('admin')
  const { error, saved, key } = await searchParams
  const settings = await configStore().list()
  const broken = settings.filter((s) => s.error)
  // What a valid value looks like, from the registry (never text from the URL).
  const requirement = (() => {
    if (error !== 'invalid' || !key) return null
    const r = REGISTRY.get(key)?.parse(undefined)
    return r && !r.ok ? r.error : null
  })()

  const groups = GROUPS.map((g) => ({ ...g, items: settings.filter((s) => g.prefixes.includes(s.key.split('.')[0])) }))
  const rest = settings.filter((s) => !GROUPS.some((g) => g.prefixes.includes(s.key.split('.')[0])))
  if (rest.length) groups.push({ title: 'Other', icon: 'settings', sub: '', prefixes: [], items: rest })

  return (
    <>
      <PageHeader
        title="Settings"
        lead="Each setting comes from its environment variable if that is set, otherwise from here, otherwise its default. Changes reach every instance within a few seconds."
      />

      {error && (
        <Notice tone="bad" role="alert">
          {ERRORS[error] ?? 'The setting could not be saved.'}
          {key && REGISTRY_LABEL(settings, key) ? ` ${REGISTRY_LABEL(settings, key)} ${requirement ?? ''}.` : ''}
        </Notice>
      )}
      {saved && !error && (
        <Notice tone="ok" role="status">
          Saved. Every instance of the app picks the change up within a few seconds.
        </Notice>
      )}
      {broken.length > 0 && (
        <Notice tone="bad" role="alert">
          <strong>Invalid settings.</strong> {broken.map((s) => `${s.label} (${s.envVar}) ${s.error}`).join('; ')}. Until fixed, each uses its
          default, or is off if it is a secret.
        </Notice>
      )}

      {groups
        .filter((g) => g.items.length > 0)
        .map((g) => (
          <Card key={g.title} title={g.title} icon={g.icon} sub={g.sub} flush className="setting-group">
            <div role="list" aria-label={g.title}>
              {g.items.map((s) => (
                <div className="setting-row" role="listitem" key={s.key}>
                  <div>
                    <div className="source-name">{s.label}</div>
                    <div className="muted small">{s.description}</div>
                    <div className="source-meta" style={{ marginTop: '0.2rem' }}>
                      {s.envVar}
                    </div>
                  </div>
                  <div className="setting-value">
                    {s.type === 'secret' ? (
                      <Pill tone={s.isSet && !s.error ? 'ok' : 'muted'} dot>
                        {s.isSet ? 'set' : 'not set'}
                      </Pill>
                    ) : (
                      <code title={String(s.value ?? '')}>{String(s.value ?? '') || '—'}</code>
                    )}
                    <Pill tone={s.source === 'environment' ? 'info' : s.source === 'database' ? 'accent' : 'muted'}>{SOURCE_LABEL[s.source]}</Pill>
                    {s.error && (
                      <div className="tone-bad small" role="note">
                        invalid: {s.error}
                      </div>
                    )}
                  </div>
                  <SettingForm setting={s} canEdit={!s.ownerOnly || atLeast(access.role, 'owner')} />
                </div>
              ))}
            </div>
          </Card>
        ))}
    </>
  )
}

function REGISTRY_LABEL(settings: ResolvedSetting[], key: string): string | null {
  return settings.find((s) => s.key === key)?.label ?? null
}

function SettingForm({ setting, canEdit }: { setting: ResolvedSetting; canEdit: boolean }) {
  if (setting.source === 'environment') return <span className="muted small" style={{ textAlign: 'right' }}>Change {setting.envVar} in the environment</span>
  if (!canEdit) return <span className="muted small" style={{ textAlign: 'right' }}>Only the owner can change this</span>
  const id = `setting-${setting.key.replace(/\W/g, '-')}`
  if (setting.type === 'bool') {
    return (
      <form action={updateSettingAction} className="settings-edit">
        <input type="hidden" name="key" value={setting.key} />
        <label htmlFor={id} className="visually-hidden">
          New value for {setting.label}
        </label>
        <select id={id} name="value" defaultValue={setting.value ? 'true' : 'false'}>
          <option value="true">on</option>
          <option value="false">off</option>
        </select>
        <SubmitButton className="btn btn-sm">Save</SubmitButton>
        {setting.source === 'database' && (
          <button className="btn btn-sm" type="submit" name="clear" value="1">
            Reset
          </button>
        )}
      </form>
    )
  }
  return (
    <form action={updateSettingAction} className="settings-edit">
      <input type="hidden" name="key" value={setting.key} />
      <label htmlFor={id} className="visually-hidden">
        New value for {setting.label}
      </label>
      <input
        id={id}
        name="value"
        type={setting.type === 'secret' ? 'password' : 'text'}
        inputMode={setting.type === 'int' ? 'numeric' : undefined}
        autoComplete="off"
        placeholder={setting.type === 'secret' ? (setting.isSet ? 'replace…' : 'set…') : String(setting.value ?? '')}
        defaultValue={setting.type === 'secret' ? undefined : String(setting.value ?? '')}
      />
      <SubmitButton className="btn btn-sm">Save</SubmitButton>
      {setting.source === 'database' && (
        <button className="btn btn-sm" type="submit" name="clear" value="1">
          {setting.type === 'secret' ? 'Remove' : 'Reset'}
        </button>
      )}
    </form>
  )
}
