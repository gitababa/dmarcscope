// Source identification: match a sending IP's reverse-DNS base domain against
// a curated list of known email services, and classify unknown sources by
// their authentication fingerprint. The key signal for forwarders is that
// DKIM signatures survive forwarding while SPF never does — so "DKIM passes,
// SPF fails" at volume marks a probable forwarder rather than a threat.

export type SourceCategory =
  | 'known' // identified third-party or own infrastructure
  | 'aligned' // unidentified but fully DMARC-compliant
  | 'forwarder' // DKIM survives, SPF fails — classic forwarding fingerprint
  | 'partial' // mixed results, needs configuration attention
  | 'unknown' // fails everything — threat or misconfigured sender

export type SourceIdentity = {
  name: string | null
  category: SourceCategory
}

// base_domain (from reverse DNS) → service name. Curated for the senders that
// actually show up in DMARC data; extend as new ones appear in your reports.
const KNOWN_SENDERS: Record<string, string> = {
  'google.com': 'Google (Gmail / Workspace)',
  '1e100.net': 'Google infrastructure',
  'amazonses.com': 'Amazon SES',
  'outlook.com': 'Microsoft 365',
  'protection.outlook.com': 'Microsoft 365',
  'sendgrid.net': 'SendGrid (Twilio)',
  'mailgun.org': 'Mailgun',
  'mailgun.net': 'Mailgun',
  'mcsv.net': 'Mailchimp',
  'mcdlv.net': 'Mailchimp',
  'rsgsv.net': 'Mailchimp (Mandrill)',
  'sparkpostmail.com': 'SparkPost',
  'postmarkapp.com': 'Postmark',
  'mtasv.net': 'Postmark',
  'zoho.com': 'Zoho Mail',
  'zohomail.com': 'Zoho Mail',
  'yahoodns.net': 'Yahoo',
  'yahoo.com': 'Yahoo',
  'messagingengine.com': 'Fastmail',
  'fastmail.com': 'Fastmail',
  'hubspotemail.net': 'HubSpot',
  'exacttarget.com': 'Salesforce Marketing Cloud',
  'salesforce.com': 'Salesforce',
  'pphosted.com': 'Proofpoint',
  'ppe-hosted.com': 'Proofpoint Essentials',
  'mimecast.com': 'Mimecast',
  'iphmx.com': 'Cisco Secure Email',
  'klaviyomail.com': 'Klaviyo',
  'customeriomail.com': 'Customer.io',
  'braze.com': 'Braze',
  'sailthru.com': 'Sailthru',
  'protonmail.ch': 'Proton Mail',
  'icloud.com': 'Apple iCloud Mail',
  'mail.ru': 'Mail.ru',
  'ovh.net': 'OVH',
  'secureserver.net': 'GoDaddy',
  'emailsrvr.com': 'Rackspace Email',
  'infomaniak.com': 'Infomaniak',
  'mimecastreport.com': 'Mimecast',
  'forwardemail.net': 'ForwardEmail (forwarder)',
  'improvmx.com': 'ImprovMX (forwarder)',
  'simplelogin.co': 'SimpleLogin (forwarder)',
  'pobox.com': 'Pobox (forwarder)',
}

// Services whose entire business is forwarding — even when identified by name,
// classify as forwarder so alignment failures aren't flagged as threats.
const FORWARDER_DOMAINS = new Set([
  'forwardemail.net',
  'improvmx.com',
  'simplelogin.co',
  'pobox.com',
  '1e100.net',
])

export function identifySource(input: {
  reverse_dns: string | null
  base_domain: string | null
  // Optional hints from the ingest worker's offline IP database.
  provider_name?: string | null
  as_name?: string | null
  total: number
  dkim_passed: number
  spf_passed: number
  dmarc_passed: number
}): SourceIdentity {
  const base = (input.base_domain || '').toLowerCase()
  const rdns = (input.reverse_dns || '').toLowerCase()

  let name: string | null = null
  let matchedDomain: string | null = null
  if (base && KNOWN_SENDERS[base]) {
    name = KNOWN_SENDERS[base]
    matchedDomain = base
  } else if (rdns) {
    for (const domain of Object.keys(KNOWN_SENDERS)) {
      if (rdns === domain || rdns.endsWith(`.${domain}`)) {
        name = KNOWN_SENDERS[domain]
        matchedDomain = domain
        break
      }
    }
  }

  const { total, dkim_passed, spf_passed, dmarc_passed } = input
  if (total === 0) return { name: name || input.provider_name || input.as_name || null, category: name ? 'known' : 'unknown' }

  const dkimRate = dkim_passed / total
  const spfRate = spf_passed / total
  const dmarcRate = dmarc_passed / total

  if (matchedDomain && FORWARDER_DOMAINS.has(matchedDomain)) {
    return { name, category: 'forwarder' }
  }
  if (name) return { name, category: 'known' }

  // No reverse-DNS match. The network owner (from the IP database) is still a
  // useful label, but owning the network is not the same as being a
  // configured sender — anyone can rent a cloud IP — so the category comes
  // from how the mail actually authenticates.
  const label = input.provider_name || input.as_name || null
  if (dmarcRate >= 0.98) return { name: label, category: 'aligned' }
  // Forwarder fingerprint: DKIM survives the hop, SPF breaks.
  if (dkimRate >= 0.8 && spfRate <= 0.2) return { name: label, category: 'forwarder' }
  if (dmarcRate === 0) return { name: label, category: 'unknown' }
  return { name: label, category: 'partial' }
}

export const CATEGORY_LABELS: Record<SourceCategory, string> = {
  known: 'Known sender',
  aligned: 'Aligned',
  forwarder: 'Likely forwarder',
  partial: 'Needs attention',
  unknown: 'Unknown / threat',
}

export const CATEGORY_TONE: Record<SourceCategory, 'ok' | 'warn' | 'bad' | 'muted'> = {
  known: 'ok',
  aligned: 'ok',
  forwarder: 'muted',
  partial: 'warn',
  unknown: 'bad',
}

// Remediation guidance shown on the Issues page when a recognizable service is
// failing alignment. Keyed by the KNOWN_SENDERS display name; use
// remediationFor() to look one up from any source label.
const REMEDIATION: Record<string, string> = {
  'Google (Gmail / Workspace)':
    'Add include:_spf.google.com to SPF and enable DKIM in Google Admin (Apps → Google Workspace → Gmail → Authenticate email), then add the generated TXT record.',
  'Amazon SES':
    'Enable Easy DKIM in the SES console (3 CNAME records) and configure a custom MAIL FROM domain so SPF aligns with your domain instead of amazonses.com.',
  'Microsoft 365':
    'Add include:spf.protection.outlook.com to SPF and enable DKIM signing in the Microsoft 365 Defender portal (Email authentication settings → DKIM), which creates two CNAME records.',
  'SendGrid (Twilio)':
    'Complete Domain Authentication in SendGrid settings — it creates CNAME records that fix both DKIM signing and SPF alignment via a return-path subdomain.',
  Mailchimp:
    'Verify the domain in Mailchimp (Website → Domains) and add its CNAME records to enable DKIM alignment.',
  'Mailchimp (Mandrill)':
    'Add the Mandrill DKIM TXT record and SPF include as shown in Mandrill Settings → Domains.',
  Mailgun:
    'Verify the sending domain in Mailgun and add its SPF include + DKIM TXT record.',
  HubSpot:
    'Connect the domain in HubSpot Settings → Domains & URLs → Email Sending Domain — this sets up DKIM CNAMEs.',
  Klaviyo:
    'Set up a dedicated sending domain in Klaviyo (Settings → Email → Domain) to get DKIM + SPF alignment.',
  Postmark:
    'Verify the domain with DKIM in Postmark (Sender Signatures) and set a custom Return-Path for SPF alignment.',
  'Zoho Mail':
    'Enable DKIM for the domain in Zoho Mail Admin (Email Authentication) and add the SPF include for your region (include:zohomail.com or include:zohomail.eu).',
}

// Source labels come from two places (the curated list above and the ingest
// worker's IP database), so match on the service name rather than exactly.
const REMEDIATION_KEYWORDS: Array<[RegExp, string]> = [
  [/sendgrid/i, 'SendGrid (Twilio)'],
  [/mandrill/i, 'Mailchimp (Mandrill)'],
  [/mailchimp/i, 'Mailchimp'],
  [/mailgun/i, 'Mailgun'],
  [/hubspot/i, 'HubSpot'],
  [/klaviyo/i, 'Klaviyo'],
  [/postmark/i, 'Postmark'],
  [/zoho/i, 'Zoho Mail'],
  [/amazon ses|amazonses/i, 'Amazon SES'],
  [/microsoft|outlook|office ?365/i, 'Microsoft 365'],
  [/google|gmail/i, 'Google (Gmail / Workspace)'],
]

export function remediationFor(identity: SourceIdentity): string {
  if (identity.name) {
    if (REMEDIATION[identity.name]) return REMEDIATION[identity.name]
    for (const [pattern, key] of REMEDIATION_KEYWORDS) {
      if (pattern.test(identity.name)) return REMEDIATION[key]
    }
  }
  return CATEGORY_REMEDIATION[identity.category]
}

export const CATEGORY_REMEDIATION: Record<SourceCategory, string> = {
  known: 'Known service failing alignment — usually missing DKIM setup or SPF include for this specific domain.',
  aligned: 'This source is passing; no action needed.',
  forwarder:
    'Forwarded mail: SPF always breaks in transit, and DMARC passes only if the original DKIM signature survives. Usually not actionable on your side — ensure your own mail is DKIM-signed so forwards still align.',
  partial:
    'Mixed results — some mail aligns, some does not. Often one mail stream (e.g. a specific app or subdomain) is missing DKIM. Compare the DKIM/SPF pass rates to see which mechanism to fix.',
  unknown:
    'Nothing about this source aligns with your domain. Either a service nobody configured (check with your teams) or spoofing. If spoofing, a p=quarantine/reject policy is what stops it.',
}
