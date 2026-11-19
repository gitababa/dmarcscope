import { describe, expect, it } from 'vitest'
import { domainHealth, gradeFor, overallHealth } from '@/lib/health'

describe('domainHealth', () => {
  it('gives no score without mail', () => {
    expect(domainHealth({ total: 0, dmarcPass: 0, dkimPass: 0, policy: 'reject' })).toMatchObject({ score: null, grade: null, tone: 'muted' })
  })

  it('gives full marks to a fully aligned, enforced domain', () => {
    const h = domainHealth({ total: 1000, dmarcPass: 1000, dkimPass: 1000, policy: 'reject' })
    expect(h.score).toBe(100)
    expect(h.grade).toBe('A')
    expect(h.factors.map((f) => f.points)).toEqual([50, 30, 20])
  })

  it('scores authentication from 80% (0) to 100% (50)', () => {
    expect(domainHealth({ total: 100, dmarcPass: 80, dkimPass: 0, policy: 'none' }).score).toBe(0)
    expect(domainHealth({ total: 100, dmarcPass: 90, dkimPass: 0, policy: 'none' }).score).toBe(25)
    expect(domainHealth({ total: 100, dmarcPass: 50, dkimPass: 0, policy: 'none' }).score).toBe(0)
  })

  it('weighs the policy', () => {
    const base = { total: 100, dmarcPass: 100, dkimPass: 100 }
    expect(domainHealth({ ...base, policy: 'reject' }).score).toBe(100)
    expect(domainHealth({ ...base, policy: 'quarantine' }).score).toBe(90)
    expect(domainHealth({ ...base, policy: 'none' }).score).toBe(70)
    expect(domainHealth({ ...base, policy: null }).score).toBe(70)
  })

  it('takes points off for failing DNS checks, never below zero', () => {
    const h = domainHealth({ total: 100, dmarcPass: 100, dkimPass: 100, policy: 'reject', dns: { dmarc: 'fail', spf: 'fail' } })
    expect(h.score).toBe(80)
    expect(h.factors.at(-1)).toMatchObject({ key: 'dns', points: -20 })
    expect(domainHealth({ total: 100, dmarcPass: 0, dkimPass: 0, policy: 'none', dns: { dmarc: 'fail' } }).score).toBe(0)
    expect(domainHealth({ total: 100, dmarcPass: 100, dkimPass: 100, policy: 'reject', dns: { dmarc: 'warn' } }).score).toBe(100)
  })
})

describe('gradeFor / overallHealth', () => {
  it('maps scores to grades', () => {
    expect([95, 90, 89, 75, 74, 60, 59, 40, 39, 0].map(gradeFor)).toEqual(['A', 'A', 'B', 'B', 'C', 'C', 'D', 'D', 'F', 'F'])
  })

  it('weights by volume and skips domains without a score', () => {
    const big = domainHealth({ total: 900, dmarcPass: 900, dkimPass: 900, policy: 'reject' }) // 100
    const small = domainHealth({ total: 100, dmarcPass: 0, dkimPass: 0, policy: 'none' }) // 0
    const empty = domainHealth({ total: 0, dmarcPass: 0, dkimPass: 0, policy: null })
    expect(overallHealth([{ total: 900, health: big }, { total: 100, health: small }, { total: 0, health: empty }])).toBe(90)
    expect(overallHealth([{ total: 0, health: empty }])).toBeNull()
  })
})
