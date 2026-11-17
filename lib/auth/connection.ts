// Which OpenID Connect connection sign-in uses right now:
//   AUTH_PROVIDER=oidc     the OIDC_* environment variables (as in 1.1.0)
//   AUTH_PROVIDER unset    the connection activated in the panel, if any
//   proxy modes, none      no single sign-on in the app

import type { Env } from '../config'
import { configStore } from '../settings'
import { settingsFromRow } from '../sso'
import { authProvider } from './index'
import { type OidcSettings, oidcSettingsFromEnv } from './oidc'

export async function currentOidcSettings(env: Env = process.env): Promise<{ settings: OidcSettings; label: string | null } | null> {
  const provider = authProvider(env)
  if (provider === 'oidc') return { settings: oidcSettingsFromEnv(env), label: env.OIDC_PROVIDER_NAME?.trim() || null }
  if (provider !== 'local') return null
  const { sso } = await configStore().snapshot()
  if (!sso) return null
  return { settings: settingsFromRow(sso, env), label: sso.button_label || null }
}
