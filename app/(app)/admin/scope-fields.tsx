// The two fields of a domain limit: everyone's domains, or only these.

export function ScopeFields({ id, mode, domains }: { id: string; mode: 'all' | 'limited'; domains: string[] }) {
  return (
    <>
      <fieldset className="field">
        <legend className="small">Domains</legend>
        <label className="small" style={{ display: 'block' }}>
          <input type="radio" name="mode" value="all" defaultChecked={mode === 'all'} /> Every domain
        </label>
        <label className="small" style={{ display: 'block' }}>
          <input type="radio" name="mode" value="limited" defaultChecked={mode === 'limited'} /> Only these (an empty list shows nothing)
        </label>
      </fieldset>
      <div className="field">
        <label htmlFor={`${id}-domains`}>Allowed domains</label>
        <textarea id={`${id}-domains`} name="domains" rows={3} defaultValue={domains.join('\n')} placeholder="example.com" aria-describedby={`${id}-hint`} />
        <div id={`${id}-hint`} className="field-hint">
          One per line. A domain may be added before its first report arrives. Ignored while “Every domain” is chosen.
        </div>
      </div>
    </>
  )
}
