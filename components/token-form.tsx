'use client'

// A form whose action returns a token once: it is shown here, with a note that
// it will not be shown again, and is gone on the next navigation.

import { useActionState, type ReactNode } from 'react'
import { SubmitButton } from './client'
import { Notice } from './ui'

export type TokenFormState = { error?: string; token?: string; name?: string }

const ERRORS: Record<string, string> = {
  'invalid:name': 'Give the token a name (up to 100 characters).',
  'invalid:scopes': 'Choose at least one scope.',
  'invalid:mode': 'Choose all domains or only some.',
  'invalid:domains': 'One of the domains is not a valid domain name.',
  'invalid:expires': 'Expiry must be a whole number of days from 1 to 365.',
  limit: 'There are too many active tokens. Revoke one first.',
  not_allowed: 'You are not allowed to do that.',
  invalid: 'That value is not valid.',
}

export function TokenForm({
  action,
  children,
  submit,
}: {
  action: (prev: TokenFormState, form: FormData) => Promise<TokenFormState>
  children: ReactNode
  submit: string
}) {
  const [state, run] = useActionState(action, {} as TokenFormState)
  return (
    <>
      {state.error && (
        <Notice tone="bad" role="alert">
          {ERRORS[state.error] ?? 'That could not be done.'}
        </Notice>
      )}
      {state.token && (
        <Notice tone="ok" role="status">
          <p>
            Token <strong>{state.name}</strong> created. Copy it now: it is shown only once and cannot be recovered.
          </p>
          <p>
            <code className="token" style={{ overflowWrap: 'anywhere' }}>
              {state.token}
            </code>
          </p>
        </Notice>
      )}
      <form action={run} className="form-grid">
        {children}
        <SubmitButton className="btn">{submit}</SubmitButton>
      </form>
    </>
  )
}
