// Turns a problem source's stats + the domain's expanded SPF into a
// human-readable diagnosis: is this forwarding, a service that was never set
// up for the domain, an envelope-alignment issue, or spoofing?

import type { ProblemSource } from './queries'
import type { SpfExpansion } from './spf'
import { matchIpInNetworks } from './spf'

export type Diagnosis = {
  // one-line verdict for the card header area
  verdict: string
  // detail bullets explaining where the failing number comes from
  details: string[]
  // 'ok' → benign (forwarding), 'warn' → config fix needed, 'bad' → unauthorized/spoofing
  tone: 'ok' | 'warn' | 'bad'
  // whether the per-service remediation hint is worth showing
  showRemediation: boolean
}

function pctOf(part: number, whole: number): string {
  if (whole === 0) return '0%'
  return `${Math.round((part / whole) * 100)}%`
}

const n = (v: number) => v.toLocaleString('en-US')

export function diagnoseSource(s: ProblemSource, spf: SpfExpansion | undefined): Diagnosis {
  const details: string[] = []

  // --- SPF authorization: is the sending IP in the domain's SPF at all? ---
  let authorized: boolean | null = null // null = unknown (no expansion available)
  if (spf) {
    const match = spf.has_spf ? matchIpInNetworks(s.source_ip, Array.isArray(spf.networks) ? spf.networks : []) : null
    if (match) {
      authorized = true
      details.push(
        `This IP is authorized by ${s.domain}'s SPF (${match.via === 'top-level' ? `directly, ${match.cidr}` : `via ${match.via}, ${match.cidr}`}).`
      )
    } else if (spf.incomplete) {
      // Part of the record could not be resolved at the last check, so a
      // miss proves nothing. Leave `authorized` unknown rather than accuse.
      details.push(
        `${s.domain}'s SPF record could not be fully resolved at the last DNS check, so whether this IP is authorized is unknown. Run the DNS checks again.`
      )
    } else if (!spf.has_spf) {
      details.push(`${s.domain} publishes no SPF record — no sender can pass SPF for it.`)
      authorized = false
    } else {
      authorized = false
      details.push(`This IP is not covered by ${s.domain}'s SPF record.`)
    }
  }

  // --- Failure composition ---
  // Every failing message is in exactly one of four groups, by which
  // authentication it carried for some *other* domain.
  const failing = s.failing
  const both = Math.min(s.fail_with_both, failing)
  const dkimOnly = Math.max(0, s.fail_with_valid_dkim_sig - both)
  const spfOnly = Math.max(0, s.fail_with_raw_spf_pass - both)
  const none = Math.max(0, failing - both - dkimOnly - spfOnly)
  const envelope = s.top_fail_envelope ? ` (envelope domain mostly ${s.top_fail_envelope})` : ''

  if (both > 0) {
    details.push(
      `${n(both)} of the failing messages (${pctOf(both, failing)}) were DKIM-signed and SPF-authenticated by a different domain${envelope} — how a service sends when it uses its own domain instead of ${s.domain}.`
    )
  }
  if (dkimOnly > 0) {
    details.push(
      `${n(dkimOnly)} (${pctOf(dkimOnly, failing)}) carry a valid DKIM signature from another domain but did not pass SPF — typical of mail relayed or forwarded by an intermediary that re-signs it.`
    )
  }
  if (spfOnly > 0) {
    details.push(
      `${n(spfOnly)} (${pctOf(spfOnly, failing)}) passed SPF for a different envelope domain${both > 0 ? '' : envelope} and had no valid DKIM signature — a Return-Path alignment problem, or a forwarder that rewrites the envelope and breaks the signature.`
    )
  }
  if (none > 0) {
    details.push(`${n(none)} (${pctOf(none, failing)}) carried no valid authentication for any domain.`)
  }

  // --- Verdict ---
  const share = (part: number) => (failing > 0 ? part / failing : 0)
  const failShare = s.total_messages > 0 ? failing / s.total_messages : 0

  if (authorized === true && share(both + dkimOnly) >= 0.7) {
    return {
      verdict: 'Likely forwarded or relayed mail — the sender is authorized; the failures happen at downstream hops. Usually no action needed.',
      details,
      tone: 'ok',
      showRemediation: false,
    }
  }
  if (authorized === true && share(spfOnly) >= 0.5) {
    return {
      verdict: 'Envelope (Return-Path) alignment issue — the sender is authorized, but bounces use a different domain and the mail is not DKIM-signed for yours.',
      details,
      tone: 'warn',
      showRemediation: true,
    }
  }
  if (authorized === true) {
    return {
      verdict: 'Authorized sender with mixed failures — see the breakdown below.',
      details,
      tone: none > 0 ? 'warn' : 'ok',
      showRemediation: none > 0,
    }
  }

  // Not authorized by SPF, or SPF status unknown.
  if (share(both) >= 0.5) {
    return {
      verdict:
        'A service is sending as this domain using its own domain for DKIM and SPF. If it is yours, set up domain authentication (custom DKIM and Return-Path) in that service; if not, your DMARC policy handles it.',
      details,
      tone: 'warn',
      showRemediation: true,
    }
  }
  if (authorized === false && spf?.has_spf) {
    return {
      verdict:
        failShare >= 0.5
          ? 'Unauthorized sender — not in SPF and most of its mail fails. Either a service to onboard or spoofing.'
          : 'Not in SPF — if this is a legitimate service, add its include; otherwise your DMARC policy handles it.',
      details,
      tone: 'bad',
      showRemediation: true,
    }
  }
  if (authorized === false) {
    return {
      verdict: 'The domain has no SPF record, so nothing can be authorized by SPF. Publish one, and make sure legitimate mail is DKIM-signed.',
      details,
      tone: 'bad',
      showRemediation: true,
    }
  }
  if (share(none) >= 0.7) {
    return {
      verdict: 'Mail with no valid authentication at all — spoofing, or a server sending without SPF or DKIM.',
      details,
      tone: 'bad',
      showRemediation: true,
    }
  }
  return {
    verdict: 'Failing alignment — see the breakdown below.',
    details,
    tone: 'warn',
    showRemediation: true,
  }
}
