// The SMTP client, against a TLS stand-in.

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { SmtpError, buildMessage, sendMail } from '@/lib/alerts/smtp'
import { makeCert, startSmtp } from '../helpers/smtp-server'

describe('SMTP client', () => {
  let cert: ReturnType<typeof makeCert>
  beforeAll(() => {
    cert = makeCert()
  })
  afterAll(() => cert.cleanup())

  const cfg = (port: number, security: 'ssl' | 'starttls', over = {}) => ({ host: '127.0.0.1', port, security, username: 'alerts', password: 'pw-canary', from: 'alerts@example.com', ...over })
  const msg = { to: ['a@example.com', 'b@example.com'], subject: 'Alert: new source', text: 'line one\r\n.dot line\r\nlast' }

  for (const mode of ['ssl', 'starttls'] as const) {
    it(`sends over ${mode} with sign-in, dot stuffing and a base64 body`, async () => {
      const s = await startSmtp({ mode, ...cert })
      try {
        await sendMail(cfg(s.port, mode), msg, { ca: cert.cert })
        const got = s.received[0]
        expect(got.starttls).toBe(mode === 'starttls')
        expect(got.auth[0]).toBe('\0alerts\0pw-canary')
        expect(got.from).toBe('<alerts@example.com>')
        expect(got.rcpt).toEqual(['<a@example.com>', '<b@example.com>'])
        expect(got.data).toMatch(/^Subject: Alert: new source\r$/m)
        const body = got.data.split('\r\n\r\n')[1]
        expect(Buffer.from(body.replace(/\r\n/g, ''), 'base64').toString()).toBe(msg.text)
      } finally {
        await s.close()
      }
    })
  }

  it('refuses to send unencrypted when STARTTLS is not offered', async () => {
    const s = await startSmtp({ mode: 'starttls', advertiseStarttls: false, ...cert })
    try {
      await expect(sendMail(cfg(s.port, 'starttls'), msg, { ca: cert.cert })).rejects.toThrow(/STARTTLS/)
      expect(s.received).toHaveLength(0)
    } finally {
      await s.close()
    }
  })

  it('never sends credentials to a server whose certificate is not trusted', async () => {
    const s = await startSmtp({ mode: 'ssl', ...cert })
    try {
      await expect(sendMail(cfg(s.port, 'ssl'), msg)).rejects.toThrow()
      expect(s.received).toHaveLength(0)
    } finally {
      await s.close()
    }
  })

  it('reports a sign-in refusal', async () => {
    const s = await startSmtp({ mode: 'ssl', authOk: false, ...cert })
    try {
      await expect(sendMail(cfg(s.port, 'ssl'), msg, { ca: cert.cert })).rejects.toThrow(/sign-in.*535/)
    } finally {
      await s.close()
    }
  })

  it('reports an unreachable server', async () => {
    await expect(sendMail(cfg(1, 'ssl'), msg, { ca: cert.cert })).rejects.toThrow()
  })

  it('refuses a line break in the subject, and bad addresses', async () => {
    // A subject with a line break is encoded, so it cannot start a new header.
    const built = buildMessage({ from: 'a@example.com' }, { to: ['x@example.com'], subject: 'hi\r\nBcc: evil@example.com', text: '' })
    expect(built).not.toMatch(/^Bcc:/im)
    // A raw header value with a line break is refused outright.
    expect(() => buildMessage({ from: 'a@example.com\r\nBcc: evil@example.com' }, { to: ['x@example.com'], subject: 'hi', text: '' })).toThrow(SmtpError)
    await expect(sendMail(cfg(1, 'ssl'), { ...msg, to: ['x@example.com\r\nRCPT TO:<evil@example.com>'] })).rejects.toThrow(/recipient/)
    await expect(sendMail(cfg(1, 'ssl', { from: 'bad' }), msg)).rejects.toThrow(/sender/)
    await expect(sendMail(cfg(1, 'ssl'), { ...msg, to: [] })).rejects.toThrow(/recipient/)
  })

  it('encodes a non-ASCII subject (RFC 2047)', () => {
    const m = buildMessage({ from: 'a@example.com' }, { to: ['x@example.com'], subject: 'Alerte : domaine é', text: 'x' })
    expect(m).toMatch(/^Subject: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/m)
  })
})
