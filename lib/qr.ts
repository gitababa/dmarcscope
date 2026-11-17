// QR code for TOTP enrolment, drawn as one SVG path on the server (no client
// script, no image request). The text is an otpauth:// URI, which is ASCII.

import qrcode from 'qrcode-generator'

export function qrPath(text: string): { size: number; path: string } {
  const qr = qrcode(0, 'M')
  qr.addData(text, 'Byte')
  qr.make()
  const n = qr.getModuleCount()
  let path = ''
  for (let row = 0; row < n; row++) {
    for (let col = 0; col < n; col++) {
      if (qr.isDark(row, col)) path += `M${col} ${row}h1v1h-1z`
    }
  }
  return { size: n, path }
}
