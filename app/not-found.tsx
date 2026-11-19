import Link from 'next/link'

export default function NotFound() {
  return (
    <main className="auth-wrap">
      <div className="card auth-card">
        <div className="eyebrow">404</div>
        <h1 style={{ marginTop: 0 }}>Page not found</h1>
        <p>That address doesn&apos;t exist in this dashboard.</p>
        <Link href="/" className="btn btn-primary btn-block">
          Go to overview
        </Link>
      </div>
    </main>
  )
}
