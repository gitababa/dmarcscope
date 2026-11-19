'use server'

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { cookieOptions, purposeCookieName } from '@/lib/auth/session'

// Forgets the recovery codes the browser was holding for /welcome.
export async function acknowledgeRecoveryCodesAction(): Promise<void> {
  ;(await cookies()).set(purposeCookieName('recovery'), '', cookieOptions(0))
  // The deployment guide opens once, to finish setting up the platform.
  redirect('/admin?guide=1')
}
