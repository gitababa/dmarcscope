// "Credentials are never readable through the web app": no web-app source
// decrypts purpose 'mailbox'. Only the worker does (ingestor/serve.py); the
// one exception is the operator's rotation script, which re-encrypts them.

import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

const ROOT = path.resolve(__dirname, '../..')
const DIRS = ['app', 'lib', 'components', 'proxy.ts', 'instrumentation.ts', 'scripts']
const ALLOWED = new Set(['scripts/secrets-reencrypt.mjs'])

function files(p: string): string[] {
  const abs = path.join(ROOT, p)
  let st
  try {
    st = statSync(abs)
  } catch {
    return []
  }
  if (st.isFile()) return /\.(ts|tsx|mjs|js)$/.test(p) ? [p] : []
  return readdirSync(abs).flatMap((f) => files(path.join(p, f)))
}

describe('mailbox secrets in the web app', () => {
  const sources = DIRS.flatMap(files).filter((f) => !ALLOWED.has(f))

  it('scans the web app', () => {
    expect(sources).toContain('lib/mail.ts')
    expect(sources.length).toBeGreaterThan(40)
  })

  it('never decrypts purpose mailbox', () => {
    const offenders = sources.filter((f) => {
      const text = readFileSync(path.join(ROOT, f), 'utf8')
      // Any decrypt call within reach of the purpose, in either order.
      return /decrypt\w*\([^;]{0,300}['"`]mailbox['"`]/s.test(text) || /['"`]mailbox['"`][^;]{0,300}decrypt\w*\(/s.test(text)
    })
    expect(offenders).toEqual([])
  })

  it('names the purpose only where it is encrypted', () => {
    const naming = sources.filter((f) => /purpose:\s*['"`]mailbox['"`]/.test(readFileSync(path.join(ROOT, f), 'utf8')))
    expect(naming).toEqual(['lib/crypto.ts'])
    const crypto = readFileSync(path.join(ROOT, 'lib/crypto.ts'), 'utf8')
    expect(crypto).toMatch(/export function encryptMailboxSecret[^}]*encrypt\(\{ secret: appSecret\(env\), purpose: 'mailbox'/)
  })
})

// Alert channel secrets (webhook URLs, signing secrets) are decrypted in one
// place: the sender. Everything else only encrypts and shows "set".
describe('alert channel secrets in the web app', () => {
  const sources = DIRS.flatMap(files).filter((f) => !ALLOWED.has(f))

  it('decrypts purpose alert only in lib/alerts/deliver.ts', () => {
    const offenders = sources.filter((f) => /decryptSecret\(\s*['"`]alert['"`]/.test(readFileSync(path.join(ROOT, f), 'utf8')))
    expect(offenders).toEqual(['lib/alerts/deliver.ts'])
  })

  it('never sends a saved address or secret to the browser', () => {
    const admin = readFileSync(path.join(ROOT, 'lib/alerts/admin.ts'), 'utf8')
    const listing = admin.slice(admin.indexOf('export async function listChannels'), admin.indexOf('export async function listRules'))
    expect(listing).not.toMatch(/\bc\.secret\b(?! IS NOT NULL)/)
  })
})
