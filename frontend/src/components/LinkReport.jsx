function riskLevel(risk) {
  if (risk >= 70) return 'scam'
  if (risk >= 40) return 'suspicious'
  return 'safe'
}

export default function LinkReport({ links, t }) {
  if (!links.length) return null

  return (
    <section className="card">
      <h3>{t.links}</h3>
      <ul className="links">
        {links.map((l) => {
          const sb = l.safe_browsing_hit === true ? t.sbHit : l.safe_browsing_hit === false ? t.sbClean : t.sbUnknown
          const sbClass = l.safe_browsing_hit === true ? 'bad' : l.safe_browsing_hit === false ? 'good' : 'muted'
          const young = l.domain_age_days !== null && l.domain_age_days < 30
          return (
            <li key={l.original_url} className={`link link-${riskLevel(l.risk)}`}>
              <code className="url">{l.original_url}</code>
              <dl>
                {l.final_url && l.redirects.length > 0 && (
                  <>
                    <dt>{t.goesTo}</dt>
                    <dd><code>{l.final_url}</code></dd>
                  </>
                )}
                <dt>{t.safeBrowsing}</dt>
                <dd className={sbClass}>{sb}</dd>
                <dt>{t.domainAge}</dt>
                <dd className={young ? 'bad' : ''}>
                  {l.domain_age_days === null ? t.unknown : `${l.domain_age_days.toLocaleString()} ${t.days}`}
                </dd>
                {l.lookalike_of && (
                  <>
                    <dt>{t.lookalike}</dt>
                    <dd className="bad">{l.lookalike_of}</dd>
                  </>
                )}
              </dl>
            </li>
          )
        })}
      </ul>
    </section>
  )
}
