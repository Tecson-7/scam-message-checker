"""Link-check tests with a fake network (httpx.MockTransport) - no real requests, no API keys."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx

from app.services.links import check_links, find_lookalike

PUBLIC_IP = "93.184.216.34"


def fake_resolve(mapping=None):
    mapping = mapping or {}

    async def resolve(host):
        if host in mapping:
            value = mapping[host]
            if value is None:
                raise OSError("no such host")
            return [value]
        return [PUBLIC_IP]
    return resolve


def rdap_response(days_old):
    date = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
    return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": date}]})


def make_client(sb_flagged=(), ages=None, redirects=None):
    """Fake internet: redirects {url: location}, RDAP ages {domain: days}, Safe Browsing flagged URLs."""
    ages, redirects = ages or {}, redirects or {}

    def handler(request: httpx.Request):
        url = str(request.url)
        if request.url.host == "safebrowsing.googleapis.com":
            import json
            entries = json.loads(request.content)["threatInfo"]["threatEntries"]
            matches = [{"threat": {"url": e["url"]}, "threatType": "SOCIAL_ENGINEERING"}
                       for e in entries if e["url"] in sb_flagged]
            return httpx.Response(200, json={"matches": matches} if matches else {})
        if request.url.host == "rdap.org":
            domain = request.url.path.rsplit("/", 1)[-1]
            return rdap_response(ages[domain]) if domain in ages else httpx.Response(404)
        if url in redirects:
            return httpx.Response(301, headers={"location": redirects[url]})
        return httpx.Response(200)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(urls, client, resolve=None, api_key="test-key"):
    return asyncio.run(check_links(urls, client=client, resolve=resolve or fake_resolve(), api_key=api_key))


# ---------- lookalikes ----------

def test_lookalikes():
    assert find_lookalike("sbi-kyc-update.xyz") == "SBI"
    assert find_lookalike("hdfcbnak.com") == "HDFC Bank"
    assert find_lookalike("icicbank.com") == "ICICI Bank"
    assert find_lookalike("indiapost-track.top") == "India Post"


def test_official_domains_are_not_lookalikes():
    for host in ["www.onlinesbi.sbi", "hdfcbank.com", "amzn.in", "www.indiapost.gov.in", "sbi.co.in"]:
        assert find_lookalike(host) is None, host


def test_unrelated_domains_are_not_lookalikes():
    for host in ["swiggy.com", "taxis.com", "google.com", "sbiz.in"]:
        assert find_lookalike(host) is None, host


# ---------- pipeline ----------

def test_no_links_means_no_link_risk():
    r = asyncio.run(check_links([]))
    assert r["link_risk"] is None


def test_shortener_is_followed_to_new_lookalike_domain():
    client = make_client(
        redirects={"https://bit.ly/abc": "https://sbi-kyc-update.xyz/login"},
        ages={"sbi-kyc-update.xyz": 5, "bit.ly": 5000},
    )
    r = run(["https://bit.ly/abc"], client)
    link = r["links"][0]
    assert link["final_url"] == "https://sbi-kyc-update.xyz/login"
    assert link["domain"] == "sbi-kyc-update.xyz"
    assert link["domain_age_days"] == 5
    assert link["lookalike_of"] == "SBI"
    assert r["link_risk"] == 85


def test_safe_browsing_hit_is_max_risk():
    client = make_client(sb_flagged={"http://evil-site.xyz"})
    r = run(["evil-site.xyz"], client)
    assert r["safe_browsing_hit"] is True
    assert r["link_risk"] == 100


def test_ssrf_private_address_is_blocked():
    client = make_client()
    r = run(["http://internal.example.com/admin"], client,
            resolve=fake_resolve({"internal.example.com": "10.0.0.5"}))
    assert r["links"][0]["blocked"] is True


def test_ssrf_redirect_to_metadata_ip_is_blocked():
    client = make_client(redirects={"https://bit.ly/x": "http://169.254.169.254/latest/meta-data"})
    r = run(["https://bit.ly/x"], client)
    link = r["links"][0]
    assert link["blocked"] is True
    assert link["final_url"].startswith("http://169.254.169.254")


def test_too_many_redirects_stops():
    redirects = {f"https://loop.com/{i}": f"https://loop.com/{i + 1}" for i in range(10)}
    r = run(["https://loop.com/0"], make_client(redirects=redirects))
    assert r["links"][0]["error"] == "too many redirects"


def test_old_official_link_is_low_risk():
    client = make_client(ages={"amzn.in": 4000})
    r = run(["amzn.in/d/abc12"], client)
    assert r["link_risk"] == 0
    assert r["links"][0]["safe_browsing_hit"] is False


def test_without_api_key_safe_browsing_is_unknown_and_not_cached():
    r = run(["example.com"], make_client(), api_key=None)
    assert r["links"][0]["safe_browsing_hit"] is None
    assert r["fresh"] == []


def test_unresolvable_domain_still_gets_safe_browsing_checked():
    client = make_client(sb_flagged={"http://gone.xyz"})
    r = run(["gone.xyz"], client, resolve=fake_resolve({"gone.xyz": None}))
    assert r["links"][0]["error"] == "domain does not resolve"
    assert r["safe_browsing_hit"] is True
