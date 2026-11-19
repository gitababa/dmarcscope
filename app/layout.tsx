import type { Metadata, Viewport } from 'next'
import { cookies } from 'next/headers'
import { getAppName } from '@/lib/settings'
import './globals.css'

export async function generateMetadata(): Promise<Metadata> {
  const name = await getAppName()
  return {
    title: { default: name, template: `%s · ${name}` },
    description: 'DMARC, SPF and DKIM monitoring for your sending domains.',
    robots: { index: false, follow: false },
  }
}

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#f5f7fa' },
    { media: '(prefers-color-scheme: dark)', color: '#070b12' },
  ],
}

// The colour theme is read from a cookie on the server, so the first paint
// is already right (no flash, and no inline script for the CSP to allow).
export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const theme = (await cookies()).get('theme')?.value
  const forced = theme === 'light' || theme === 'dark' ? theme : undefined
  return (
    <html lang="en" data-theme={forced}>
      <body>{children}</body>
    </html>
  )
}
