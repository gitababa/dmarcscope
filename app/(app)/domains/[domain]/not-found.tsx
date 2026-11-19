import Link from 'next/link'
import { EmptyState } from '@/components/ui'

export default function DomainNotFound() {
  return (
    <EmptyState
      icon="globe"
      title="Domain not found"
      action={
        <Link href="/domains" className="btn">
          All domains
        </Link>
      }
    >
      No DMARC reports have been received for this domain, or the name doesn&apos;t match one being tracked. Domains appear here
      automatically once their first report is ingested.
    </EmptyState>
  )
}
