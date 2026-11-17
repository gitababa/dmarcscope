'use server'

// Server actions. Next.js rejects cross-origin action requests, and each
// action re-checks the caller's session and role itself.

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { authProvider, hasSignInPage } from '@/lib/auth'
import { endSessionUrl } from '@/lib/auth/oidc'
import { audit, getAccessWithRole, getAuth } from '@/lib/auth/server'
import { cookieOptions, sessionCookieName } from '@/lib/auth/session'
import { isValidDomainName, runAndStoreDnsCheck } from '@/lib/dns-run'
import { parseRange, rangeParam } from '@/lib/format'

export async function signOutAction(): Promise<void> {
  const provider = authProvider()
  if (!hasSignInPage(provider)) redirect('/')
  const auth = await getAuth()
  if (auth.status === 'ok' || auth.status === 'forbidden') await audit('sign_out')
  const jar = await cookies()
  jar.set(sessionCookieName(), '', cookieOptions(0))
  // Only a single sign-on session has a provider session to end.
  const viaIdp = provider === 'oidc' && !(auth.status === 'ok' && auth.session.role === 'owner' && auth.session.identity.sub.startsWith('user:'))
  redirect((viaIdp ? await endSessionUrl() : null) ?? '/login?signed_out=1')
}

export async function runDnsCheckAction(formData: FormData): Promise<void> {
  const access = await getAccessWithRole('admin')
  if (!access) {
    await audit('action_refused', { action: 'dns_check', reason: 'role' })
    redirect('/denied')
  }

  const domain = String(formData.get('domain') || '').trim().toLowerCase()
  if (!isValidDomainName(domain)) redirect('/')

  const outcome = await runAndStoreDnsCheck(access.domains, domain)
  await audit('dns_check', { domain, outcome: outcome.status }, `domain:${domain}`)

  const path = `/domains/${encodeURIComponent(domain)}`
  revalidatePath(path)
  const query = new URLSearchParams({ range: rangeParam(parseRange(String(formData.get('range') || ''))) })
  if (outcome.status === 'cooldown') query.set('notice', 'cooldown')
  redirect(`${path}?${query}`)
}
