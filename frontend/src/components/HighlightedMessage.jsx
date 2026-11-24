// Shows the original message with red-flag phrases highlighted.
// The backend gives positions in Python characters (code points); Array.from() splits
// the JS string the same way, so emoji and Tamil/Hindi text don't shift the highlights.

const GROUP_LABELS = {
  urgency: 'Urgency', threat: 'Threat', kyc: 'KYC / documents', otp_request: 'Asks for OTP/PIN',
  payment: 'Payment request', prize: 'Prize / reward', job_offer: 'Job offer', parcel: 'Parcel',
  electricity: 'Electricity', contact_push: 'Click / call pressure', llm: 'Flagged by AI',
}

export default function HighlightedMessage({ text, highlights }) {
  const chars = Array.from(text)
  const spans = [...highlights].sort((a, b) => a.start - b.start)

  const parts = []
  let pos = 0
  spans.forEach((h, i) => {
    if (h.start < pos) return // overlapping span - backend already merges, this is a safety net
    if (h.start > pos) parts.push(<span key={`t${i}`}>{chars.slice(pos, h.start).join('')}</span>)
    parts.push(
      <mark key={`h${i}`} className={`flag flag-${h.group}`} title={GROUP_LABELS[h.group] || h.group}>
        {chars.slice(h.start, h.end).join('')}
      </mark>,
    )
    pos = h.end
  })
  if (pos < chars.length) parts.push(<span key="end">{chars.slice(pos).join('')}</span>)

  return <p className="message">{parts}</p>
}
