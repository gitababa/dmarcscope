import type { Metadata } from 'next'
import { SubmitButton } from '@/components/client'
import { Pill } from '@/components/ui'
import { atLeast } from '@/lib/auth/roles'
import { listPendingRequests } from '@/lib/admin'
import { requirePageRole } from '@/lib/auth/server'
import { REGISTRY, type ResolvedSetting, configStore } from '@/lib/settings'
import { updateSettingAction } from './actions'
import { AdminNav } from './nav'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Settings' }

const ERRORS: Record<string, string> = {
  owner_only: 'Only the owner can change that setting.',
  unknown: 'There is no such setting.',
  managed_by_environment: 'That setting is managed by an environment variable and cannot be changed here.',
  invalid: 'That value is not valid.',
}

const SOURCE_LABEL: Record<ResolvedSetting['source'], string> = {
  environment: 'managed by environment',
  database: 'set here',
  default: 'default',
}

export default async function AdminSettingsPage({ searchParams }: { searchParams: Promise<{ error?: string; saved?: string; key?: string }> }) {
  const access = await requirePageRole('admin')
  const { error, saved, key } = await searchParams
  const [settings, pending] = await Promise.all([configStore().list(), listPendingRequests(access)])
  const broken = settings.filter((s) => s.error)
  // What a valid value looks like, from the registry (never text from the URL).
  const requirement = (() => {
    if (error !== 'invalid' || !key) return null
    const r = REGISTRY.get(key)?.parse(undefined)
    return r && !r.ok ? r.error : null
  })()

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <p>Each setting comes from its environment variable if that is set, otherwise from here, otherwise its default.</p>
        </div>
      </div>
      <AdminNav current="/admin" pending={pending.length} />

      {error && (
        <div className="notice bad" role="alert">
          {ERRORS[error] ?? 'The setting could not be saved.'}
          {key && REGISTRY_LABEL(settings, key) ? ` ${REGISTRY_LABEL(settings, key)} ${requirement ?? ''}.` : ''}
        </div>
      )}
      {saved && !error && (
        <div className="notice ok" role="status">
          Saved. Every instance of the app picks the change up within a few seconds.
        </div>
      )}
      {broken.length > 0 && (
        <div className="notice bad" role="alert">
          <span>
            <strong>Invalid settings.</strong> {broken.map((s) => `${s.label} (${s.envVar}) ${s.error}`).join('; ')}. Until fixed,
            each uses its default, or is off if it is a secret.
          </span>
        </div>
      )}

      <div className="card flush" role="list" aria-label="Settings">
        {settings.map((s) => (
          <div className="setting-row" role="listitem" key={s.key}>
            <div>
              <div className="source-name">{s.label}</div>
              <div className="source-meta">
                {s.key} · {s.envVar}
              </div>
              <div className="muted small">{s.description}</div>
            </div>
            <div className="setting-value">
              {s.type === 'secret' ? (
                <Pill tone={s.isSet && !s.error ? 'ok' : 'muted'}>{s.isSet ? 'set' : 'not set'}</Pill>
              ) : (
                <code>{String(s.value ?? '')}</code>
              )}{' '}
              <Pill tone={s.source === 'environment' ? 'info' : 'muted'}>{SOURCE_LABEL[s.source]}</Pill>
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
    </>
  )
}

function REGISTRY_LABEL(settings: ResolvedSetting[], key: string): string | null {
  return settings.find((s) => s.key === key)?.label ?? null
}

function SettingForm({ setting, canEdit }: { setting: ResolvedSetting; canEdit: boolean }) {
  if (setting.source === 'environment') return <span className="muted small">Change {setting.envVar}</span>
  if (!canEdit) return <span className="muted small">Owner only</span>
  const id = `setting-${setting.key.replace(/\W/g, '-')}`
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
