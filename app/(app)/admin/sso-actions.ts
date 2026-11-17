'use server'

// Single sign-on actions (owner only). Each re-checks the caller's role;
// lib/sso.ts holds the rules (only a successful test activates) and writes
// the audit entries, including for refusals.

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { audit, currentActor, getAccessWithRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { type SsoActor, SsoRefusal, activateDraft, deactivate, discardDraft, saveDraft, startDraft } from '@/lib/sso'

async function owner(action: string): Promise<SsoActor> {
  const access = await getAccessWithRole('owner')
  if (!access) {
    await audit('action_refused', { action, reason: 'not_allowed' })
    redirect((await getAccessWithRole('admin')) ? '/admin/sso?error=not_allowed' : '/denied')
  }
  return { ...(await currentActor()), role: access.role }
}

async function run(action: string, done: string, fn: (actor: SsoActor) => Promise<unknown>): Promise<never> {
  const actor = await owner(action)
  try {
    await fn(actor)
  } catch (err) {
    if (err instanceof SsoRefusal) redirect(`/admin/sso?error=${err.code}${err.field ? `&field=${err.field}` : ''}`)
    throw err
  }
  revalidatePath('/admin/sso')
  redirect(`/admin/sso?done=${done}`)
}

const text = (form: FormData, name: string, max = 2000) => {
  const v = form.get(name)
  return typeof v === 'string' ? v.slice(0, max) : ''
}

export async function startDraftAction(form: FormData): Promise<void> {
  await run('sso_draft_started', 'editing', (a) => startDraft(getPool(), a, form.get('preset')))
}

export async function saveDraftAction(form: FormData): Promise<void> {
  await run('sso_draft_saved', 'saved', (a) =>
    saveDraft(getPool(), a, {
      preset: form.get('preset'),
      issuer: text(form, 'issuer', 600),
      clientId: text(form, 'client_id', 400),
      clientSecret: text(form, 'client_secret', 2001),
      clearSecret: form.get('public_client') === '1',
      scopes: text(form, 'scopes', 600),
      emailClaim: text(form, 'email_claim', 200),
      groupsClaim: text(form, 'groups_claim', 200),
      requiredClaims: text(form, 'required_claims', 1100),
      buttonLabel: text(form, 'button_label', 100),
    })
  )
}

export async function discardDraftAction(): Promise<void> {
  await run('sso_draft_discarded', 'discarded', (a) => discardDraft(getPool(), a))
}

export async function activateAction(): Promise<void> {
  await run('sso_activated', 'activated', (a) => activateDraft(getPool(), a))
}

export async function deactivateAction(form: FormData): Promise<void> {
  if (form.get('confirm') !== 'yes') redirect('/admin/sso?confirm=deactivate')
  await run('sso_deactivated', 'deactivated', (a) => deactivate(getPool(), a))
}
