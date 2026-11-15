// Auth helpers for server components, server actions and route handlers.

import { cache } from 'react'
import { cookies, headers } from 'next/headers'
import { redirect } from 'next/navigation'
import { authProvider, authenticate } from './index'
import type { AuthResult, Session } from './types'

// One authentication per request, however many components ask.
export const getAuth = cache(async (): Promise<AuthResult> => {
  const [h, c] = await Promise.all([headers(), cookies()])
  return authenticate({ headers: h, cookie: (name) => c.get(name)?.value })
})

// For pages: returns the session or redirects away.
export async function requireViewer(): Promise<Session> {
  const auth = await getAuth()
  if (auth.status === 'ok') return auth.session
  if (auth.status === 'unauthenticated' && authProvider() === 'oidc') redirect('/login')
  redirect('/denied')
}

// For actions and route handlers: null unless the caller is an admin.
export async function getAdminSession(): Promise<Session | null> {
  const auth = await getAuth()
  return auth.status === 'ok' && auth.session.role === 'admin' ? auth.session : null
}

// Structured audit line on stdout, for whatever log pipeline the deployment has.
export function audit(event: string, fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ level: 'info', type: 'audit', event, time: new Date().toISOString(), ...fields }))
}
