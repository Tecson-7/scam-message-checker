import HighlightedMessage from './HighlightedMessage.jsx'
import LinkReport from './LinkReport.jsx'
import WhatToDo from './WhatToDo.jsx'

const ICONS = { scam: '⛔', suspicious: '⚠️', safe: '✅' }

export default function Result({ result, text, t }) {
  const { verdict, score } = result

  return (
    <div className="result" aria-live="polite">
      <section className={`verdict verdict-${verdict}`}>
        <div className="verdict-top">
          <span className="verdict-icon" aria-hidden="true">{ICONS[verdict]}</span>
          <div>
            <h2>{t.verdict[verdict]}</h2>
            <p>{t.verdictHint[verdict]}</p>
          </div>
        </div>

        <div className="meter" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={score}
             aria-label={t.riskScore}>
          <div className="meter-fill" style={{ width: `${Math.max(score, 3)}%` }} />
        </div>
        <div className="meter-label">
          <span>{t.riskScore}</span>
          <strong>{score}/100</strong>
        </div>

        <div className="chips">
          {result.category && <span className="chip">{t.category[result.category] || result.category}</span>}
          {result.impersonated_entity && (
            <span className="chip chip-warn">{t.pretendsToBe}: {result.impersonated_entity}</span>
          )}
        </div>
      </section>

      <WhatToDo verdict={verdict} t={t} />

      {result.explanation && (
        <section className="card">
          <h3>{t.explanation}</h3>
          <p className="explanation">{result.explanation}</p>
        </section>
      )}

      <section className="card">
        <h3>{t.redFlags}</h3>
        <HighlightedMessage text={text} highlights={result.highlights} />
        {result.highlights.length === 0 && <p className="muted small">{t.noRedFlags}</p>}
      </section>

      {verdict !== 'safe' && (
        <section className="card">
          <h3>{t.signals}</h3>
          <ul className="reasons">
            {result.reasons.map((r) => <li key={r}>{r}</li>)}
          </ul>
        </section>
      )}

      <LinkReport links={result.links} t={t} />
    </div>
  )
}
