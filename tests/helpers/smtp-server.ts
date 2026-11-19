// A TLS SMTP stand-in for the client tests: implicit TLS or STARTTLS, records
// what it was sent, and can be told to refuse sign-in. The certificate is
// generated with openssl for 127.0.0.1 and trusted through the client's `ca`
// option, so certificate verification stays on in the tests.

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import tls from 'node:tls'

export type Received = { auth: string[]; from: string | null; rcpt: string[]; data: string; starttls: boolean }

export function makeCert(): { key: string; cert: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'smtp-test-'))
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${dir}/k.pem`, '-out', `${dir}/c.pem`, '-days', '2', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' })
  const key = readFileSync(`${dir}/k.pem`, 'utf8')
  const cert = readFileSync(`${dir}/c.pem`, 'utf8')
  return { key, cert, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

export async function startSmtp(opts: { mode: 'ssl' | 'starttls'; key: string; cert: string; authOk?: boolean; advertiseStarttls?: boolean }) {
  const received: Received[] = []
  const handle = (sock: net.Socket, upgraded: boolean) => {
    const cur: Received = { auth: [], from: null, rcpt: [], data: '', starttls: upgraded }
    let inData = false
    let buf = ''
    let secure = opts.mode === 'ssl' || upgraded
    const send = (s: string) => sock.write(`${s}\r\n`)
    const onData = (d: Buffer) => {
      buf += d.toString('utf8')
      let i
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i)
        buf = buf.slice(i + 2)
        if (inData) {
          if (line === '.') {
            inData = false
            received.push({ ...cur })
            send('250 queued')
          } else cur.data += `${line}\r\n`
          continue
        }
        const cmd = line.toUpperCase()
        if (cmd.startsWith('EHLO')) {
          send('250-localhost')
          if (opts.mode === 'starttls' && !secure && opts.advertiseStarttls !== false) send('250-STARTTLS')
          send('250 AUTH PLAIN LOGIN')
        } else if (cmd === 'STARTTLS') {
          send('220 go ahead')
          sock.removeListener('data', onData)
          const t = new tls.TLSSocket(sock, { isServer: true, key: opts.key, cert: opts.cert })
          handle(t, true)
          return
        } else if (cmd.startsWith('AUTH PLAIN')) {
          cur.auth.push(Buffer.from(line.slice(11), 'base64').toString('utf8'))
          send(opts.authOk === false ? '535 5.7.8 bad credentials' : '235 ok')
        } else if (cmd.startsWith('MAIL FROM:')) {
          cur.from = line.slice(10)
          send('250 ok')
        } else if (cmd.startsWith('RCPT TO:')) {
          cur.rcpt.push(line.slice(8))
          send('250 ok')
        } else if (cmd === 'DATA') {
          inData = true
          send('354 go')
        } else if (cmd === 'QUIT') {
          send('221 bye')
          sock.end()
        } else send('500 what')
      }
    }
    sock.on('data', onData)
    sock.on('error', () => {})
    if (!upgraded) send('220 localhost ESMTP')
  }
  const server =
    opts.mode === 'ssl'
      ? tls.createServer({ key: opts.key, cert: opts.cert }, (s) => handle(s, false))
      : net.createServer((s) => handle(s, false))
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  return {
    port: (server.address() as net.AddressInfo).port,
    received,
    close: () => new Promise<void>((r) => server.close(() => r())),
  }
}
