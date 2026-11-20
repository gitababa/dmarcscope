import { describe, expect, it } from 'vitest'
import { appUrl, envBool, envInt, envList, hasValidBearer, safeEqual } from '@/lib/config'

describe('config helpers', () => {
  it('parses lists, booleans and bounded ints', () => {
    expect(envList(' A@x.com, ,b@x.com ')).toEqual(['a@x.com', 'b@x.com'])
    expect(envList(undefined)).toEqual([])
    expect(envBool('TRUE')).toBe(true)
    expect(envBool('0')).toBe(false)
    expect(envBool(undefined, true)).toBe(true)
    expect(envInt('abc', 5, 1, 10)).toBe(5)
    expect(envInt('99', 5, 1, 10)).toBe(10)
  })

  it('safeEqual compares exactly', () => {
    expect(safeEqual('abc', 'abc')).toBe(true)
    expect(safeEqual('abc', 'abd')).toBe(false)
    expect(safeEqual('abc', 'abcd')).toBe(false)
    expect(safeEqual('', '')).toBe(true)
  })

  it('bearer check fails closed', () => {
    const secret = 's'.repeat(32)
    expect(hasValidBearer(`Bearer ${secret}`, { CRON_SECRET: secret })).toBe(true)
    expect(hasValidBearer(`Bearer ${secret}x`, { CRON_SECRET: secret })).toBe(false)
    expect(hasValidBearer(secret, { CRON_SECRET: secret })).toBe(false)
    expect(hasValidBearer(null, { CRON_SECRET: secret })).toBe(false)
    expect(hasValidBearer('Bearer ', { CRON_SECRET: '' })).toBe(false)
    expect(hasValidBearer('Bearer undefined', {})).toBe(false)
    // too short to be a real secret
    expect(hasValidBearer('Bearer abc', { CRON_SECRET: 'abc' })).toBe(false)
  })

  it('appUrl requires configuration in production', () => {
    expect(appUrl({ APP_URL: 'https://d.example.com/some/path' })).toBe('https://d.example.com')
    expect(appUrl({})).toBe('http://localhost:3000')
    expect(() => appUrl({ NODE_ENV: 'production' })).toThrow(/APP_URL/)
    expect(() => appUrl({ APP_URL: 'ftp://x' })).toThrow()
    expect(() => appUrl({ APP_URL: 'nonsense' })).toThrow()
  })

  it('appUrl falls back to the production address Vercel sets, and APP_URL still wins', () => {
    const vercel = { NODE_ENV: 'production', VERCEL: '1', VERCEL_PROJECT_PRODUCTION_URL: 'DMARC.Example.com' }
    expect(appUrl(vercel)).toBe('https://dmarc.example.com')
    expect(appUrl({ ...vercel, APP_URL: 'https://other.example.com' })).toBe('https://other.example.com')
    // Only on Vercel, and only a host name: nothing else becomes the app's address.
    expect(() => appUrl({ NODE_ENV: 'production', VERCEL_PROJECT_PRODUCTION_URL: 'dmarc.example.com' })).toThrow(/APP_URL/)
    expect(() => appUrl({ ...vercel, VERCEL_PROJECT_PRODUCTION_URL: 'evil.example/x?y=' })).toThrow(/APP_URL/)
  })
})
