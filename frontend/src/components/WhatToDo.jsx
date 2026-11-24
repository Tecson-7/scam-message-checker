// Hand-written safety advice. Turns the helpline and websites into tappable links.

const LINKS = [
  { match: 'cybercrime.gov.in', href: 'https://cybercrime.gov.in' },
  { match: '1930', href: 'tel:1930' },
  { match: 'Sanchar Saathi (Chakshu)', href: 'https://sancharsaathi.gov.in' },
]

function linkify(step) {
  for (const { match, href } of LINKS) {
    const i = step.indexOf(match)
    if (i !== -1) {
      return (
        <>
          {step.slice(0, i)}
          <a href={href} target="_blank" rel="noreferrer">{match}</a>
          {step.slice(i + match.length)}
        </>
      )
    }
  }
  return step
}

export default function WhatToDo({ verdict, t }) {
  const steps = verdict === 'safe' ? t.stepsSafe : t.stepsRisky
  return (
    <section className={`card todo todo-${verdict}`}>
      <h3>{t.whatToDo}</h3>
      <ol>
        {steps.map((s) => <li key={s}>{linkify(s)}</li>)}
      </ol>
    </section>
  )
}
