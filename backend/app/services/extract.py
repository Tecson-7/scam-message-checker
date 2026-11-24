"""Step 3 - Extract URLs, Indian phone numbers, UPI IDs, emails and amounts."""
import re

# TLDs we recognise for links written without http/www (e.g. "bit.ly/abc", "sbi-kyc.xyz")
_TLDS = (
    r"co\.in|gov\.in|org\.in|net\.in|com|in|org|net|xyz|top|info|ly|me|io|link|site|"
    r"online|club|live|app|cc|tk|ml|ga|cf|gq|sbi|shop|store|vip|icu|buzz|cfd|sbs|click"
)

URL_RE = re.compile(
    rf"""(?ix)
    (?<![@\w.])                                   # not part of an email / UPI ID
    (
      (?:https?://|www\.)[^\s<>"']+               # http://..., www....
      |
      (?:[a-z0-9-]+\.)+(?:{_TLDS})(?![a-z0-9-])   # bare domain
      (?:/[^\s<>"']*)?                            # optional path
    )
    """
)

PHONE_RE = re.compile(r"(?<![\d+])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
# UPI: handle@bank with no ".com" after it (that would be an email)
UPI_RE = re.compile(r"\b[\w.-]{2,256}@[a-zA-Z]{2,64}\b(?!\.[a-zA-Z])")
AMOUNT_RE = re.compile(r"(?i)(?:₹|\brs\.?|\binr)\s*(\d[\d,]*(?:\.\d+)?)")

_TRAILING = ".,;:!?)]}'\""


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def normalize_phone(raw: str) -> str:
    """Return the last 10 digits (drops +91 / spaces / dashes)."""
    return re.sub(r"\D", "", raw)[-10:]


def extract(text: str) -> dict:
    urls = [m.group(1).rstrip(_TRAILING) for m in URL_RE.finditer(text)]
    phones = [normalize_phone(m.group(0)) for m in PHONE_RE.finditer(text)]
    emails = EMAIL_RE.findall(text)
    upi_ids = [u for u in UPI_RE.findall(text) if u not in emails]
    amounts = [float(a.replace(",", "")) for a in AMOUNT_RE.findall(text)]

    return {
        "urls": _dedupe(urls),
        "phones": _dedupe(phones),
        "upi_ids": _dedupe(upi_ids),
        "emails": _dedupe(emails),
        "amounts": _dedupe(amounts),
    }
