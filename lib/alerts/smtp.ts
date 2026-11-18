// A small SMTP client on node:net and node:tls (plain-text mail, one message
// per connection). Certificate verification is always on and there is no
// unencrypted mode: it speaks implicit TLS (port 465) or STARTTLS (587), then
// AUTH PLAIN or LOGIN when credentials are configured.

import net from 'node:net'
import tls from 'node:tls'

export type SmtpConfig = {
  host: string
  port: number
  security: 'ssl' | 'starttls'
  username: string | null
  password: string | null
  from: string
}

export type SmtpMessage = { to: string[]; subject: string; text: string }

export class SmtpError extends Error {}

const CONNECT_MS = 10_000
const TOTAL_MS = 30_000

const ADDRESS = /^[^\s@"<>()\\,;:\r\n]{1,64}@[A-Za-z0-9.-]{1,253}$/

export function isAddress(s: string): boolean {
  return ADDRESS.test(s)
}

// A header value may never carry a line break: that is how extra headers
// (Bcc:) get injected.
function header(name: string, value: string): string {
  if (/[\r\n\x00]/.test(value)) throw new SmtpError(`refusing a line break in the ${name} header`)
  return `${name}: ${value}`
}

// RFC 2047, only when needed.
function encodeSubject(subject: string): string {
  // eslint-disable-next-line no-control-regex
  if (/^[\x20-\x7e]*$/.test(subject)) return subject
  return `=?UTF-8?B?${Buffer.from(subject, 'utf8').toString('base64')}?=`
}

export function buildMessage(cfg: Pick<SmtpConfig, 'from'>, msg: SmtpMessage, now = new Date(), messageId?: string): string {
  const domain = cfg.from.split('@')[1]
  const body = Buffer.from(msg.text.replace(/\r?\n/g, '\r\n'), 'utf8').toString('base64').replace(/(.{76})/g, '$1\r\n')
  return [
    header('From', cfg.from),
    header('To', msg.to.join(', ')),
    header('Subject', encodeSubject(msg.subject)),
    header('Date', now.toUTCString()),
    header('Message-ID', `<${messageId ?? `${now.getTime().toString(36)}.${Math.random().toString(36).slice(2)}`}@${domain}>`),
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    'Auto-Submitted: auto-generated',
    '',
    body,
  ].join('\r\n')
}

type Reader = { next(): Promise<{ code: number; lines: string[] }> }

function makeReader(socket: net.Socket): Reader {
  let buf = ''
  const queue: Array<{ code: number; lines: string[] }> = []
  let pending: Array<{ code: number; lines: string[] }> = []
  let waiter: { resolve: (r: { code: number; lines: string[] }) => void; reject: (e: Error) => void } | null = null
  let failure: Error | null = null
  const flush = () => {
    let i
    while ((i = buf.indexOf('\r\n')) >= 0) {
      const line = buf.slice(0, i)
      buf = buf.slice(i + 2)
      const m = /^(\d{3})([ -])(.*)$/.exec(line)
      if (!m) continue
      pending.push({ code: Number(m[1]), lines: [m[3]] })
      if (m[2] === ' ') {
        const code = Number(m[1])
        queue.push({ code, lines: pending.map((p) => p.lines[0]) })
        pending = []
      }
    }
    deliver()
  }
  const deliver = () => {
    if (!waiter) return
    if (queue.length) {
      const w = waiter
      waiter = null
      w.resolve(queue.shift()!)
    } else if (failure) {
      const w = waiter
      waiter = null
      w.reject(failure)
    }
  }
  socket.on('data', (d) => {
    buf += d.toString('utf8')
    if (buf.length > 65536) socket.destroy(new SmtpError('the server sent too much'))
    flush()
  })
  socket.on('error', (e) => {
    failure = e
    deliver()
  })
  socket.on('close', () => {
    failure ??= new SmtpError('the connection closed unexpectedly')
    deliver()
  })
  return {
    next: () =>
      new Promise((resolve, reject) => {
        waiter = { resolve, reject }
        deliver()
      }),
  }
}

export async function sendMail(cfg: SmtpConfig, msg: SmtpMessage, opts: { ca?: string | Buffer } = {}): Promise<void> {
  if (!isAddress(cfg.from)) throw new SmtpError('the sender address is not valid')
  if (msg.to.length === 0 || msg.to.length > 10 || !msg.to.every(isAddress)) throw new SmtpError('the recipient list is not valid')
  const data = buildMessage(cfg, msg)

  const deadline = setTimeout(() => socket?.destroy(new SmtpError('the mail server took too long')), TOTAL_MS)
  let socket: net.Socket | tls.TLSSocket | undefined
  const tlsOpts = (s?: net.Socket): tls.ConnectionOptions => ({
    host: cfg.host,
    servername: net.isIP(cfg.host) ? undefined : cfg.host,
    ...(s ? { socket: s } : { port: cfg.port }),
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    ...(opts.ca ? { ca: opts.ca } : {}),
  })
  try {
    socket = await new Promise<net.Socket>((resolve, reject) => {
      const t = setTimeout(() => reject(new SmtpError('could not connect to the mail server in time')), CONNECT_MS)
      const s: net.Socket =
        cfg.security === 'ssl'
          ? tls.connect(tlsOpts(), () => (clearTimeout(t), resolve(s)))
          : net.connect({ host: cfg.host, port: cfg.port }, () => (clearTimeout(t), resolve(s)))
      s.once('error', (e) => (clearTimeout(t), reject(e)))
    })
    let reader = makeReader(socket)
    const expect = async (ok: number[], what: string) => {
      const r = await reader.next()
      if (!ok.includes(r.code)) throw new SmtpError(`${what}: the server answered ${r.code} ${r.lines[0] ?? ''}`.slice(0, 200))
      return r
    }
    const say = async (line: string, ok: number[], what: string) => {
      socket!.write(`${line}\r\n`)
      return expect(ok, what)
    }
    await expect([220], 'greeting')
    let ehlo = await say('EHLO dmarcscope', [250], 'EHLO')
    if (cfg.security === 'starttls') {
      if (!ehlo.lines.some((l) => /^STARTTLS\b/i.test(l))) throw new SmtpError('the server does not offer STARTTLS, and unencrypted mail is never sent')
      await say('STARTTLS', [220], 'STARTTLS')
      const plain = socket as net.Socket
      plain.removeAllListeners('data')
      socket = await new Promise<tls.TLSSocket>((resolve, reject) => {
        const s = tls.connect(tlsOpts(plain), () => resolve(s))
        s.once('error', reject)
      })
      reader = makeReader(socket)
      ehlo = await say('EHLO dmarcscope', [250], 'EHLO')
    }
    if (cfg.username && cfg.password != null) {
      const mechs = (ehlo.lines.find((l) => /^AUTH\b/i.test(l)) ?? '').toUpperCase()
      if (mechs.includes('PLAIN')) {
        await say(`AUTH PLAIN ${Buffer.from(`\0${cfg.username}\0${cfg.password}`, 'utf8').toString('base64')}`, [235], 'sign-in')
      } else if (mechs.includes('LOGIN')) {
        await say('AUTH LOGIN', [334], 'sign-in')
        await say(Buffer.from(cfg.username, 'utf8').toString('base64'), [334], 'sign-in')
        await say(Buffer.from(cfg.password, 'utf8').toString('base64'), [235], 'sign-in')
      } else {
        throw new SmtpError('the server offers no sign-in method this client supports')
      }
    }
    await say(`MAIL FROM:<${cfg.from}>`, [250], 'sender')
    for (const to of msg.to) await say(`RCPT TO:<${to}>`, [250, 251], 'recipient')
    await say('DATA', [354], 'DATA')
    // Dot stuffing: a line starting with "." gets another.
    socket.write(`${data.replace(/(^|\r\n)\./g, '$1..')}\r\n.\r\n`)
    await expect([250], 'message')
    socket.write('QUIT\r\n')
  } finally {
    clearTimeout(deadline)
    socket?.destroy()
  }
}
