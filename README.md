# Scam Message Checker

Paste an SMS/WhatsApp message → get a verdict (🔴 Scam / 🟡 Suspicious / 🟢 Likely safe), a 0–100 risk score and plain-language reasons.

**Status:** Steps 1–7 done — extraction, rule scoring, privacy masking, Postgres storage, link checks.
Next: Step 8 (Gemini classification + explanation).

## Run it locally

```bash
cd backend
python -m venv venv
# Windows:  venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
copy .env.example .env        # Mac/Linux: cp .env.example .env

uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs → `POST /api/check` → **Try it out**.

## Connect Neon + Safe Browsing (Steps 6–7)

In `backend/.env`:
```
DATABASE_URL=postgresql+psycopg://USER:PASS@ep-xxx.ap-southeast-1.aws.neon.tech/neondb?sslmode=require
SAFE_BROWSING_KEY=AIza...
```
Restart `uvicorn`. Then check:
1. `GET /health` → `"database": true`
2. Neon → **Tables**: `checks`, `links`, `reports`, `link_cache` exist
3. `POST /api/check` with `Check this http://malware.testing.google.test/testing/malware/`
   → `safe_browsing_hit: true`, verdict `scam` (Google's official test URL)
4. Send the same message twice → same `check_id`, `times_checked = 2` in Neon

Without the keys the app still works: nothing is saved and `safe_browsing_hit` is `null` (unknown).

## How link checking works

1. **SSRF guard** — only public `http(s)` addresses on ports 80/443; private, loopback and cloud-metadata IPs are blocked, re-checked on **every redirect hop**
2. **Unshorten** — redirects followed manually (max 5, 3 s timeout) with HEAD requests; the page is never rendered or downloaded
3. **Google Safe Browsing v4** — one batched call covering every URL in every redirect chain
4. **Domain age** — RDAP registration date; under 30 days is a strong red flag
5. **Lookalikes** — brand keywords and near-spellings (`hdfcbnak.com`) against a list of official domains
6. Results cached 24 h in `link_cache`

Link risk: Safe Browsing hit 100 · new lookalike 85 · new domain 70 · lookalike 60 · hidden/internal address 50.

## Tests and evaluation

```bash
cd backend
pytest                      # unit + API tests

cd ..
python eval/run_eval.py           # rules only
python eval/run_eval.py --links   # rules only vs rules + links (real network calls)
```

## Project layout

```
backend/app/
  main.py            FastAPI app, CORS, /health, creates tables on startup
  config.py          settings from .env
  db.py              engine + session (optional if DATABASE_URL is empty)
  models.py          checks, links, reports, link_cache
  repository.py      all DB reads/writes
  schemas.py         request/response models
  routers/check.py   POST /api/check pipeline
  services/
    extract.py       URLs, phones, UPI IDs, emails, amounts (regex)
    rules.py         keyword groups + combo bonuses, highlight positions
    privacy.py       masking before storage, message hash
    links.py         SSRF guard, unshorten, Safe Browsing, RDAP, lookalikes
    scorer.py        combines rules + links + LLM (re-weights missing signals)
testset/messages.csv  labelled messages (replace the samples with real ones)
eval/run_eval.py      metrics
```

## Privacy

Phone numbers, account/card digits, emails, UPI IDs and names in greetings are masked before anything is stored. A SHA-256 hash of the normalised message is used for de-duplication.

## Limitations

- The SSRF check resolves DNS and then `httpx` resolves again, so a fast DNS-rebinding attack could slip between the two. Pinning the resolved IP would close this; it's acceptable for an MVP since no page content is read.
- Some TLDs (including many `.in` subdomains) return no RDAP data, so domain age can be unknown.
- The official-domain list is hand-maintained.
- Google Safe Browsing is free for non-commercial use only; a commercial version would use the Web Risk API.
