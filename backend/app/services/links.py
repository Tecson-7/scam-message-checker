"""Step 7 - Link checks.

For every link in the message:
  1. SSRF guard   - only fetch public http(s) addresses, re-checked on every redirect hop
  2. Unshorten    - follow redirects manually (max 5, 3s timeout), never render the page
  3. Safe Browsing - one batched call for every URL in every redirect chain
  4. Domain age   - RDAP registration date
  5. Lookalike    - brand keyword / near-spelling of an official domain
Then a 0-100 risk per link; the message's link_risk is the max.
"""
import asyncio
import ipaddress
import logging
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx
import tldextract
from rapidfuzz import fuzz

from ..config import settings

MAX_LINKS = 5
MAX_REDIRECTS = 5
TIMEOUT = httpx.Timeout(3.0)
NEW_DOMAIN_DAYS = 30
SB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
RDAP_URL = "https://rdap.org/domain/{}"
USER_AGENT = "Mozilla/5.0 (compatible; ScamChecker/0.1)"

log = logging.getLogger("uvicorn.error")

_tld = tldextract.TLDExtract(suffix_list_urls=())  # bundled suffix list, no network call

# Official domains. Verify and extend this list - it's the heart of the lookalike check.
OFFICIAL = {
    "SBI":          {"keywords": ["sbi", "onlinesbi", "yonosbi"], "domains": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"]},
    "HDFC Bank":    {"keywords": ["hdfc"], "domains": ["hdfcbank.com", "hdfc.bank.in"]},
    "ICICI Bank":   {"keywords": ["icici"], "domains": ["icicibank.com", "icici.bank.in"]},
    "Axis Bank":    {"keywords": ["axisbank"], "domains": ["axisbank.com", "axis.bank.in"]},
    "Kotak":        {"keywords": ["kotak"], "domains": ["kotak.com", "kotak.bank.in"]},
    "India Post":   {"keywords": ["indiapost", "speedpost"], "domains": ["indiapost.gov.in"]},
    "TNEB":         {"keywords": ["tneb", "tangedco"], "domains": ["tnebnet.org", "tangedco.org"]},
    "Income Tax":   {"keywords": ["incometax"], "domains": ["incometax.gov.in"]},
    "UIDAI":        {"keywords": ["aadhaar", "aadhar", "uidai"], "domains": ["uidai.gov.in", "myaadhaar.uidai.gov.in"]},
    "Airtel":       {"keywords": ["airtel"], "domains": ["airtel.in", "airtel.com"]},
    "Jio":          {"keywords": ["jio"], "domains": ["jio.com"]},
    "Amazon":       {"keywords": ["amazon", "amzn"], "domains": ["amazon.in", "amazon.com", "amzn.in", "amzn.to"]},
    "Flipkart":     {"keywords": ["flipkart"], "domains": ["flipkart.com"]},
    "Paytm":        {"keywords": ["paytm"], "domains": ["paytm.com"]},
    "PhonePe":      {"keywords": ["phonepe"], "domains": ["phonepe.com"]},
    "Blue Dart":    {"keywords": ["bluedart"], "domains": ["bluedart.com"]},
    "Delhivery":    {"keywords": ["delhivery"], "domains": ["delhivery.com"]},
}
_ALL_OFFICIAL = [d for b in OFFICIAL.values() for d in b["domains"]]


# ---------- helpers ----------

def registered_domain(host: str | None) -> str | None:
    if not host:
        return None
    ext = _tld(host)
    return getattr(ext, "top_domain_under_public_suffix", None) or None


def is_official(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in _ALL_OFFICIAL)


def find_lookalike(host: str | None) -> str | None:
    """Return the brand a host is pretending to be, or None."""
    if not host:
        return None
    host = host.lower().rstrip(".")
    if is_official(host):
        return None

    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    for brand, info in OFFICIAL.items():
        for kw in info["keywords"]:
            # short keywords (sbi, jio) must be a whole token; longer ones can be inside a token
            if any(t == kw or (len(kw) >= 4 and kw in t) for t in tokens):
                return brand

    name = _tld(host).domain                       # "hdfcbnak" from "hdfcbnak.com"
    for brand, info in OFFICIAL.items():
        for d in info["domains"]:
            official_name = _tld(d).domain
            if len(official_name) >= 5 and name != official_name and fuzz.ratio(name, official_name) >= 85:
                return brand
    return None


def _with_scheme(url: str) -> str:
    return url if re.match(r"(?i)^https?://", url) else "http://" + url


# ---------- 1. SSRF guard ----------

async def _resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


async def check_target(url: str, resolve=_resolve) -> tuple[str, str | None]:
    """('ok', None) if safe to fetch, ('blocked', why) for internal targets, ('error', why) otherwise."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return "error", "invalid URL"
    if parts.scheme not in ("http", "https"):
        return "blocked", "unsupported scheme"
    if port not in (None, 80, 443):
        return "blocked", "non-standard port"
    if not parts.hostname:
        return "error", "no host"
    try:
        ipaddress.ip_address(parts.hostname)       # raw IP in the URL -> check it directly
        ips = [parts.hostname]
    except ValueError:
        try:
            ips = await resolve(parts.hostname)
        except OSError:
            return "error", "domain does not resolve"
    for ip in ips:
        if not ipaddress.ip_address(ip.split("%")[0]).is_global:
            return "blocked", "points to a private/internal address"
    return "ok", None


# ---------- 2. Unshorten ----------

async def _head(client: httpx.AsyncClient, url: str) -> httpx.Response:
    resp = await client.head(url, follow_redirects=False)
    if resp.status_code in (403, 405, 501):            # some servers refuse HEAD
        resp = await client.send(client.build_request("GET", url), stream=True, follow_redirects=False)
        await resp.aclose()                             # headers only, body never read
    return resp


async def unshorten(url: str, client: httpx.AsyncClient, resolve=_resolve) -> dict:
    chain, current = [url], url
    for _ in range(MAX_REDIRECTS + 1):
        status, why = await check_target(current, resolve)
        if status != "ok":
            return {"final_url": current, "chain": chain, "blocked": status == "blocked", "error": why}
        try:
            resp = await _head(client, current)
        except httpx.HTTPError as e:
            return {"final_url": current, "chain": chain, "blocked": False,
                    "error": f"could not open link ({type(e).__name__})"}
        if resp.is_redirect and resp.headers.get("location"):
            current = urljoin(current, resp.headers["location"])
            chain.append(current)
            continue
        return {"final_url": current, "chain": chain, "blocked": False, "error": None}
    return {"final_url": current, "chain": chain, "blocked": False, "error": "too many redirects"}


# ---------- 3. Safe Browsing ----------

async def safe_browsing(urls: list[str], client: httpx.AsyncClient, api_key: str | None) -> dict | None:
    """{url: [threat types]} for flagged URLs. None = couldn't check (no key / API error)."""
    if not api_key:
        log.warning("Safe Browsing skipped: SAFE_BROWSING_KEY is empty in .env")
        return None
    if not urls:
        return {}
    body = {
        "client": {"clientId": "scam-checker", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    try:
        r = await client.post(SB_URL, params={"key": api_key}, json=body)
        r.raise_for_status()
        data = r.json()
    except httpx.HTTPStatusError as e:
        log.warning("Safe Browsing API error %s: %s", e.response.status_code, e.response.text[:300])
        return None
    except (httpx.HTTPError, ValueError) as e:
        log.warning("Safe Browsing request failed: %s", type(e).__name__)
        return None
    hits: dict[str, list[str]] = {}
    for m in data.get("matches", []):
        hits.setdefault(m["threat"]["url"], []).append(m["threatType"])
    return hits


# ---------- 4. Domain age ----------

async def domain_age_days(domain: str | None, client: httpx.AsyncClient) -> int | None:
    if not domain:
        return None
    try:
        r = await client.get(RDAP_URL.format(domain), follow_redirects=True)
        if r.status_code != 200:
            return None
        events = r.json().get("events", [])
    except (httpx.HTTPError, ValueError):
        return None
    for ev in events:
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - created).days
    return None


# ---------- 5. Risk per link ----------

def link_risk(info: dict) -> tuple[int, list[str]]:
    risk, reasons = 0, []
    age = info["domain_age_days"]
    is_new = age is not None and age < NEW_DOMAIN_DAYS

    if info["safe_browsing_hit"]:
        risk = 100
        reasons.append("Google Safe Browsing lists this link as dangerous")
    if is_new:
        risk = max(risk, 70)
        reasons.append(f"The website was registered only {age} days ago")
    if info["lookalike_of"]:
        risk = max(risk, 85 if is_new else 60)
        reasons.append(f"The link pretends to be {info['lookalike_of']} but is not its official website")
    if info["blocked"]:
        risk = max(risk, 50)
        reasons.append("The link points to a hidden or unusual address")
    return risk, reasons


# ---------- main entry ----------

async def check_links(urls: list[str], cached: dict[str, dict] | None = None,
                      client: httpx.AsyncClient | None = None, resolve=_resolve,
                      api_key: str | None = ...) -> dict:
    """Returns {links, fresh, link_risk, safe_browsing_hit, reasons}.
    link_risk is None when the message has no links (the scorer then ignores links)."""
    urls = urls[:MAX_LINKS]
    if not urls:
        return {"links": [], "fresh": [], "link_risk": None, "safe_browsing_hit": False, "reasons": []}

    cached = cached or {}
    api_key = settings.safe_browsing_key if api_key is ... else api_key
    todo = [u for u in urls if u not in cached]

    own_client = client is None
    client = client or httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
    try:
        fresh = await _check_fresh(todo, client, resolve, api_key) if todo else []
    finally:
        if own_client:
            await client.aclose()

    by_url = {**cached, **{r["original_url"]: r for r in fresh}}
    links = [by_url[u] for u in urls]

    reasons = list(dict.fromkeys(r for l in links for r in l["reasons"]))
    return {
        "links": links,
        "fresh": [r for r in fresh if r["safe_browsing_hit"] is not None],  # only cache complete results
        "link_risk": max(l["risk"] for l in links),
        "safe_browsing_hit": any(l["safe_browsing_hit"] for l in links),
        "reasons": reasons,
    }


async def _check_fresh(urls, client, resolve, api_key) -> list[dict]:
    unshortened = await asyncio.gather(*(unshorten(_with_scheme(u), client, resolve) for u in urls))

    all_chain_urls = list(dict.fromkeys(u for res in unshortened for u in res["chain"]))
    domains = [registered_domain(urlsplit(res["final_url"]).hostname) for res in unshortened]
    unique_domains = list(dict.fromkeys(d for d in domains if d))

    sb_hits, ages = await asyncio.gather(
        safe_browsing(all_chain_urls, client, api_key),
        asyncio.gather(*(domain_age_days(d, client) for d in unique_domains)),
    )
    age_by_domain = dict(zip(unique_domains, ages))

    results = []
    for original, res, domain in zip(urls, unshortened, domains):
        threats = [] if sb_hits is None else [t for u in res["chain"] for t in sb_hits.get(u, [])]
        lookalike = next(
            (b for b in (find_lookalike(urlsplit(u).hostname) for u in reversed(res["chain"])) if b), None
        )
        info = {
            "original_url": original,
            "final_url": res["final_url"],
            "redirects": res["chain"][1:],
            "domain": domain,
            "safe_browsing_hit": None if sb_hits is None else bool(threats),
            "threat_types": sorted(set(threats)),
            "domain_age_days": age_by_domain.get(domain),
            "lookalike_of": lookalike,
            "blocked": res["blocked"],
            "error": res["error"],
        }
        info["risk"], info["reasons"] = link_risk(info)
        results.append(info)
    return results
