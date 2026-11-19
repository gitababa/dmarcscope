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
      <div className="card auth-card wide">
        <span className="row-icon bad" style={{ width: 44, height: 44, borderRadius: 12 }}>
          !
        </span>
        <h1>Something went wrong</h1>
        <p className="muted">
          The page could not be loaded. The most common causes are an unreachable database, a schema that has not been
          migrated yet (<code>npm run db:migrate</code>), or missing configuration. The server logs have the details.
        </p>
        {error.digest && (
          <p className="muted small">
            Reference for the server logs: <code>{error.digest}</code>
          </p>
        )}
        <button onClick={() => reset()} className="btn btn-primary">
          Try again
        </button>
      </div>
    </main>
  )
}
