import { SubmitButton } from '@/components/client'
import { Pill } from '@/components/ui'
import { relTime } from '@/lib/format'
import { KINDS, type MailboxKind, type MailboxRow } from '@/lib/mail'
import { createMailboxAction, updateMailboxAction } from '../mail-actions'

export const MAIL_ERRORS: Record<string, string> = {
  not_allowed: 'Only administrators can do that.',
  invalid: 'That value is not valid.',
  not_found: 'That mailbox no longer exists. This is the current state.',
  environment: 'The monitored domains are set by ALLOWED_DOMAINS on this deployment and cannot be changed here.',
  duplicate: 'That domain is in the list already.',
}

export const MAIL_FIELDS: Record<string, string> = {
  kind: 'kind of mailbox',
  name: 'Name (1 to 100 characters)',
  host: 'Server (a host name or IPv4 address, without https://)',
  port: 'Port (1 to 65535)',
  security: 'Security',
  username: 'Mailbox address / user name',
  tenant_id: 'Tenant ID (the directory ID, or a domain such as contoso.onmicrosoft.com)',
  client_id: 'Application (client) ID',
  secret: 'Secret (required for a new mailbox, or when changing its kind; a Google key must be the JSON file of a service account)',
  folder: 'Folder to read',
  processed_folder: 'Folder for processed reports (different from the folder read)',
  invalid_folder: 'Folder for messages that are not reports (different from the folder read)',
  interval_minutes: 'Check every (15 to 1440 minutes)',
  domain: 'Domain (for example example.com)',
}

const SETUP_NOTE: Record<MailboxKind, string> = {
  imap: 'Any IMAP server. Use a dedicated mailbox that receives only DMARC reports; an app password where the provider offers one.',
  microsoft:
    'An app registration with the IMAP.AccessAsApp application permission, registered in Exchange Online and given access to this one mailbox only. Step by step in docs/mail.md. Not yet verified against a real Microsoft 365 tenant.',
  google:
    'A dedicated service account with domain-wide delegation for https://mail.google.com/ only. Its key can read any mailbox of your domain: treat it as your most sensitive secret. Step by step in docs/mail.md. Not yet verified against a real Google Workspace domain.',
}

function Field({
  id,
  label,
  value,
  hint,
  required,
  type = 'text',
  pattern,
  maxLength,
  inputMode,
  placeholder,
  autoComplete = 'off',
}: {
  id: string
  label: string
  value?: string | number | null
  hint?: string
  required?: boolean
  type?: 'text' | 'email' | 'password'
  pattern?: string
  maxLength?: number
  inputMode?: 'numeric'
  placeholder?: string
  autoComplete?: string
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        name={id}
        type={type}
        defaultValue={value == null ? '' : String(value)}
        required={required}
        pattern={pattern}
        maxLength={maxLength}
        inputMode={inputMode}
        placeholder={placeholder}
        autoComplete={autoComplete}
        aria-describedby={hint ? `${id}-hint` : undefined}
        spellCheck={false}
      />
      {hint && (
        <div id={`${id}-hint`} className="field-hint">
          {hint}
        </div>
      )}
    </div>
  )
}

export function MailboxForm({ kind, mailbox }: { kind: MailboxKind; mailbox?: MailboxRow }) {
  const editing = !!mailbox
  const secretSet = editing && mailbox.secret_set && mailbox.kind === kind
  return (
    <form action={editing ? updateMailboxAction : createMailboxAction} className="form">
      {editing && <input type="hidden" name="id" value={mailbox.id} />}
      <input type="hidden" name="kind" value={kind} />
      <div className="notice" role="note">
        <span>{SETUP_NOTE[kind]}</span>
      </div>
      <Field id="name" label="Name" value={mailbox?.name ?? (kind === 'imap' ? 'DMARC reports' : `DMARC reports (${KINDS[kind].label.split(' (')[0]})`)} required maxLength={100} />
      {kind === 'imap' ? (
        <>
          <Field id="host" label="Server" value={mailbox?.host} required maxLength={253} placeholder="imap.example.com" />
          <div className="field">
            <label htmlFor="security">Security</label>
            <select id="security" name="security" defaultValue={mailbox?.security ?? 'ssl'}>
              <option value="ssl">TLS (port 993)</option>
              <option value="starttls">STARTTLS (port 143)</option>
            </select>
          </div>
          <Field id="port" label="Port" value={mailbox?.port} inputMode="numeric" pattern="\d{1,5}" maxLength={5} hint="Leave empty for the usual port." />
          <Field id="username" label="User name" value={mailbox?.username} required maxLength={320} autoComplete="off" />
        </>
      ) : (
        <>
          <div className="field">
            <span className="field-label">Server</span>
            <div>
              <code>{KINDS[kind].host}</code> <span className="muted small">(TLS, port 993; fixed for this kind)</span>
            </div>
          </div>
          <Field
            id="username"
            label="Mailbox address"
            type="email"
            value={mailbox?.username}
            required
            maxLength={320}
            hint={kind === 'microsoft' ? 'The shared mailbox the app was given access to.' : 'The mailbox the service account acts as.'}
          />
        </>
      )}
      {kind === 'microsoft' && (
        <>
          <Field id="tenant_id" label="Tenant ID" value={mailbox?.tenant_id} required maxLength={255} hint="Directory (tenant) ID from the app registration's overview." />
          <Field
            id="client_id"
            label="Application (client) ID"
            value={mailbox?.client_id}
            required
            pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
            maxLength={36}
          />
        </>
      )}
      <div className="field">
        <label htmlFor="secret">{KINDS[kind].secretLabel}</label>
        {kind === 'google' ? (
          <textarea
            id="secret"
            name="secret"
            rows={4}
            required={!secretSet}
            spellCheck={false}
            autoComplete="off"
            placeholder={secretSet ? 'set; paste a new key to replace it' : 'paste the contents of the JSON key file'}
            aria-describedby="secret-hint"
          />
        ) : (
          <input
            id="secret"
            name="secret"
            type="password"
            required={!secretSet}
            autoComplete="new-password"
            placeholder={secretSet ? 'set; type to replace' : 'not set'}
            aria-describedby="secret-hint"
          />
        )}
        <div id="secret-hint" className="field-hint">
          Stored encrypted. Only the worker can read it; this page never shows it again.
          {editing && mailbox.secret_updated_at ? ` Last changed ${new Date(mailbox.secret_updated_at).toISOString().slice(0, 10)}.` : ''}
          {kind === 'microsoft' ? ' Client secrets expire (24 months at most): note the date and replace it in time.' : ''}
        </div>
      </div>
      <details className="field">
        <summary>Folders and schedule</summary>
        <Field id="folder" label="Folder to read" value={mailbox?.folder ?? 'INBOX'} maxLength={200} />
        <Field
          id="processed_folder"
          label="Move processed reports to"
          value={mailbox?.processed_folder}
          maxLength={200}
          hint="Empty: processed reports are marked as read and stay where they are."
        />
        <Field id="invalid_folder" label="Move messages that are not reports to" value={mailbox?.invalid_folder ?? 'DMARC-Invalid'} maxLength={200} />
        <Field id="interval_minutes" label="Check every (minutes)" value={mailbox?.interval_minutes ?? 60} inputMode="numeric" pattern="\d{2,4}" maxLength={4} hint="15 to 1440." />
      </details>
      <label className="small">
        <input type="checkbox" name="enabled" value="1" defaultChecked={mailbox ? mailbox.enabled : true} /> Check on schedule
      </label>
      <div className="inline-form">
        <SubmitButton className="btn btn-primary btn-sm" pendingLabel="Saving…">
          {editing ? 'Save' : 'Add mailbox'}
        </SubmitButton>
        {!editing && (
          <a href="/admin/mail" className="small">
            Cancel
          </a>
        )}
      </div>
    </form>
  )
}

export function WorkerNotice({ alive, lastSeen }: { alive: number; lastSeen: string | null }) {
  if (alive > 0) {
    return (
      <p className="small" style={{ margin: 0 }}>
        <Pill tone="ok">worker running</Pill> {alive > 1 ? `${alive} workers are` : 'A worker is'} checking these mailboxes.
      </p>
    )
  }
  return (
    <div className="notice warn" role="note">
      <span>
        No worker is running{lastSeen ? ` (last seen ${relTime(lastSeen)})` : ''}. Mailboxes saved here are read by{' '}
        <code>python -m ingestor serve</code>, with the same <code>DATABASE_URL</code> and <code>APP_SECRET</code> as this
        app (see docs/mail.md). Until one runs, nothing is checked and tests wait.
      </span>
    </div>
  )
}

export function runState(m: Pick<MailboxRow, 'enabled' | 'last_run' | 'secret_set'>): { tone: 'ok' | 'bad' | 'warn' | 'muted' | 'info'; label: string } {
  if (!m.enabled) return { tone: 'muted', label: 'paused' }
  if (!m.secret_set) return { tone: 'warn', label: 'no secret' }
  const r = m.last_run
  if (!r) return { tone: 'info', label: 'not run yet' }
  if (!r.finished_at) return { tone: 'info', label: 'running' }
  return r.failed ? { tone: 'bad', label: 'last run failed' } : { tone: 'ok', label: 'ok' }
}

