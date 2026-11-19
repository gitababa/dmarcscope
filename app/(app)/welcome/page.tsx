import type { Metadata } from 'next'
import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { SubmitButton } from '@/components/client'
import { requirePageRole } from '@/lib/auth/server'
import { purposeCookieName } from '@/lib/auth/session'
import { unsealRecoveryCodes } from '@/lib/setup-state'
import { acknowledgeRecoveryCodesAction } from './actions'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Recovery codes' }

// Shown once, right after setup: the owner's recovery codes are only ever
// stored as digests, so this is the one chance to copy them.
export default async function WelcomePage() {
  const { session } = await requirePageRole('owner')
  const saved = await unsealRecoveryCodes((await cookies()).get(purposeCookieName('recovery'))?.value)
  if (!saved || saved.userId !== session.userId) redirect('/admin')

  return (
    <div className="card" style={{ maxWidth: 560, margin: '2rem auto 0', padding: '1.75rem' }}>
      <div className="eyebrow">Last step</div>
      <h1 style={{ marginTop: 0, fontSize: '1.4rem' }}>Save your recovery codes</h1>
      <p className="muted">
        The owner account is ready and you are signed in. If you lose your authenticator app, each of these codes
        signs you in once instead of a code from the app. Store them somewhere safe, such as a password manager.{' '}
        <strong>They will not be shown again.</strong>
      </p>
      <ul className="codes" aria-label="Recovery codes" data-testid="recovery-codes">
        {saved.codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <form action={acknowledgeRecoveryCodesAction}>
        <SubmitButton className="btn btn-primary">I have saved them</SubmitButton>
      </form>
    </div>
  )
}
