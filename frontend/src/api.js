// Backend URL: set VITE_API_URL in frontend/.env for deployment (Step 15).
export const API_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

export async function checkMessage(text, language) {
  const res = await fetch(`${API_URL}/api/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, language }),
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const detail = Array.isArray(body.detail) ? body.detail[0]?.msg : body.detail
    throw new Error(detail || `Request failed (${res.status})`)
  }
  return res.json()
}
