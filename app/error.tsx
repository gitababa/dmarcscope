'use client'

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <main className="auth-wrap">
      <div className="card" style={{ maxWidth: 560 }}>
        <h1 className="tone-bad" style={{ marginTop: 0, fontSize: '1.2rem' }}>
          Something went wrong
        </h1>
        <p className="muted">
          The page could not be loaded. The most common causes are an unreachable database, a schema that has not been
          migrated yet (<code>npm run db:migrate</code>), or missing configuration. The server logs have the details.
        </p>
        {error.digest && (
          <p className="muted small">
            Reference for the server logs: <code>{error.digest}</code>
          </p>
        )}
        <button onClick={() => reset()} className="btn">
          Try again
        </button>
      </div>
    </main>
  )
}
