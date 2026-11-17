'use server'

// Administration actions. Each re-checks the caller's role itself (the page
// that shows the form is not a permission check) and writes an audit entry,
// including for a refusal.

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { audit, currentActor, getAccessWithRole } from '@/lib/auth/server'
import { atLeast } from '@/lib/auth/roles'
import { REGISTRY, SettingError, configStore } from '@/lib/settings'

export async function updateSettingAction(formData: FormData): Promise<void> {
  const back = formData.get('back') === '/admin/sso' ? '/admin/sso' : '/admin'
  const key = String(formData.get('key') || '')
  const def = REGISTRY.get(key)
  const access = await getAccessWithRole('admin')

  if (!access || !def || (def.ownerOnly && !atLeast(access.role, 'owner'))) {
    await audit('action_refused', { action: 'setting_change', key: def ? key : '(unknown)', reason: !access ? 'role' : !def ? 'unknown_setting' : 'owner_only' })
    if (!access) redirect('/denied')
    redirect(`${back}?error=${def ? 'owner_only' : 'unknown'}`)
  }

  const clear = formData.get('clear') === '1'
  const raw = formData.get('value')
  const value = typeof raw === 'string' ? raw : ''
  // For a secret, an empty field means "keep what is there".
  if (!clear && def.type === 'secret' && value === '') redirect(back)

  try {
    await configStore().write(key, clear ? null : def.type === 'secret' ? value : value.trim(), await currentActor())
  } catch (err) {
    if (!(err instanceof SettingError)) throw err
    await audit('setting_change_refused', { key, reason: err.code })
    redirect(`${back}?error=${err.code}&key=${encodeURIComponent(key)}`)
  }
  revalidatePath('/admin', 'layout')
  redirect(back === '/admin' ? `/admin?saved=${encodeURIComponent(key)}` : `${back}?done=switched`)
}
