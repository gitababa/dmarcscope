// "What should I do next with this domain's DMARC policy?"
//
// DMARC only stops spoofing once the policy is quarantine or reject, but
// tightening it while legitimate mail still fails alignment sends that mail
// to spam. This turns the last 30 days of data into a concrete next step.

export type PolicyAdvice = {
  tone: 'ok' | 'warn' | 'bad' | 'info'
  title: string
  detail: string
}

const MIN_MESSAGES = 100
const READY_FOR_QUARANTINE = 0.98
const READY_FOR_REJECT = 0.99

function pct1(rate: number): string {
  return `${(Math.floor(rate * 1000) / 10).toFixed(1)}%`
}

export function policyAdvice(input: {
  policy: string | null
  total30d: number
  passed30d: number
}): PolicyAdvice {
  const policy = (input.policy || '').toLowerCase()
  const { total30d: total, passed30d: passed } = input
  const rate = total > 0 ? passed / total : 0

  if (total < MIN_MESSAGES) {
    return {
      tone: 'info',
      title: 'Not enough recent data to advise on policy',
      detail: `Only ${total.toLocaleString('en-US')} messages were reported in the last 30 days. Wait for more reports before changing the policy.`,
    }
  }

  if (policy === 'reject') {
    return rate >= READY_FOR_QUARANTINE
      ? {
          tone: 'ok',
          title: 'Fully enforced',
          detail: `p=reject with ${pct1(rate)} compliance over the last 30 days. Spoofed mail is rejected; keep an eye on the Issues page for new senders.`,
        }
      : {
          tone: 'bad',
          title: 'Enforced, but legitimate mail may be getting rejected',
          detail: `p=reject while only ${pct1(rate)} of mail passes DMARC. Check the Issues page: any real sender listed there is currently being rejected by receivers.`,
        }
  }

  if (policy === 'quarantine') {
    return rate >= READY_FOR_REJECT
      ? {
          tone: 'ok',
          title: 'Ready to move to p=reject',
          detail: `${pct1(rate)} compliance over the last 30 days. Remaining failures are typically forwarding or spoofing, which reject is meant to stop.`,
        }
      : {
          tone: 'warn',
          title: 'Stay on p=quarantine for now',
          detail: `${pct1(rate)} compliance over the last 30 days; aim for 99% before p=reject. Failing mail is currently going to spam — fix the senders on the Issues page.`,
        }
  }

  // p=none, or no policy seen in reports
  return rate >= READY_FOR_QUARANTINE
    ? {
        tone: 'ok',
        title: 'Ready to move to p=quarantine',
        detail: `${pct1(rate)} compliance over the last 30 days. Monitoring mode does not stop spoofing; consider p=quarantine with pct=25 first, then raise pct to 100.`,
      }
    : {
        tone: 'warn',
        title: 'Fix failing senders before enforcing',
        detail: `${pct1(rate)} compliance over the last 30 days; aim for 98% before p=quarantine. The Issues page lists which senders fail and why.`,
      }
}
