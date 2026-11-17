// Runs once when a server instance starts. With no owner yet, makes sure a
// one-time setup token exists and prints it to the log (see lib/setup.ts).
// A failure here (database not migrated yet, unreachable) is only logged:
// opening /setup tries again.

export async function register() {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return
  if (process.env.NEXT_PHASE === 'phase-production-build') return
  const [{ getPool }, { ensureSetupToken }] = await Promise.all([import('./lib/db'), import('./lib/setup')])
  try {
    await ensureSetupToken(getPool())
  } catch (err) {
    console.error('[setup] could not check for a setup token at startup:', err instanceof Error ? err.message : String(err))
  }
}
