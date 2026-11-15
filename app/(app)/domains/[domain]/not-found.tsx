import Link from 'next/link'

export default function DomainNotFound() {
  return (
    <div className="card">
      <h2 className="section-title">Domain not found</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        No DMARC reports have been received for this domain, or the name doesn&apos;t match one being tracked. Domains
        appear here automatically once their first report is ingested.
      </p>
      <Link href="/" className="btn">
        Back to overview
      </Link>
    </div>
  )
}
