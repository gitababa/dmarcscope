import type { Metadata, Viewport } from 'next'
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
    { media: '(prefers-color-scheme: light)', color: '#ffffff' },
    { media: '(prefers-color-scheme: dark)', color: '#14181f' },
  ],
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
