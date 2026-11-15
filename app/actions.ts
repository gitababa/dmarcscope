'use server'

// Server actions. Next.js rejects cross-origin action requests, and each
// action re-checks the caller's session and role itself.

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { authProvider } from '@/lib/auth'
import { endSessionUrl } from '@/lib/auth/oidc'
import { audit, getAdminSession, getAuth } from '@/lib/auth/server'
import { cookieOptions, sessionCookieName } from '@/lib/auth/session'
import { isValidDomainName, runAndStoreDnsCheck } from '@/lib/dns-run'
import { parseRange, rangeParam } from '@/lib/format'

export async function signOutAction(): Promise<void> {
  if (authProvider() !== 'oidc') redirect('/')
  const auth = await getAuth()
  if (auth.status !== 'unauthenticated') {
    audit('sign_out', { email: auth.status === 'ok' ? auth.session.identity.email : auth.identity.email })
  }
  const jar = await cookies()
  jar.set(sessionCookieName(), '', cookieOptions(0))
  redirect((await endSessionUrl()) ?? '/login?signed_out=1')
}

export async function runDnsCheckAction(formData: FormData): Promise<void> {
  const session = await getAdminSession()
  if (!session) redirect('/denied')

  const domain = String(formData.get('domain') || '').trim().toLowerCase()
  if (!isValidDomainName(domain)) redirect('/')

  const outcome = await runAndStoreDnsCheck(domain)
  audit('dns_check', { email: session.identity.email, domain, outcome: outcome.status })

  const path = `/domains/${encodeURIComponent(domain)}`
  revalidatePath(path)
  const query = new URLSearchParams({ range: rangeParam(parseRange(String(formData.get('range') || ''))) })
  if (outcome.status === 'cooldown') query.set('notice', 'cooldown')
  redirect(`${path}?${query}`)
}
