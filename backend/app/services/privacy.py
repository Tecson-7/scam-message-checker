"""Step 5 - Mask personal data before anything is stored, and hash for dedup."""
import hashlib
import re

from .extract import EMAIL_RE, PHONE_RE, UPI_RE

CARD_RE = re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b")
LONG_DIGITS_RE = re.compile(r"\b(?:[xX*]*\d){8,18}\b")       # account numbers, incl. "XX1234567"
GREETING_RE = re.compile(r"\b((?i:dear|hi|hello|mr\.?|mrs\.?|ms\.?))\s+([A-Z][a-z]+)")
NOT_NAMES = {"Customer", "Consumer", "User", "Sir", "Madam", "Member", "Client", "Valued", "All", "Team"}


def _mask_phone(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))[-10:]
    return f"{digits[:2]}XXXXXX{digits[-2:]}"


def _keep_last4(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    return "XXXX" + digits[-4:]


def _mask_upi(m: re.Match) -> str:
    handle, bank = m.group(0).split("@", 1)
    return f"{handle[:2]}***@{bank}"


def mask_text(text: str) -> str:
    text = EMAIL_RE.sub("[email]", text)
    text = UPI_RE.sub(_mask_upi, text)
    text = CARD_RE.sub(_keep_last4, text)
    text = PHONE_RE.sub(_mask_phone, text)
    text = LONG_DIGITS_RE.sub(_keep_last4, text)
    text = GREETING_RE.sub(
        lambda m: m.group(0) if m.group(2) in NOT_NAMES else f"{m.group(1)} [name]", text
    )
    return text


def message_hash(text: str) -> str:
    """Same message with different spacing/case -> same hash."""
    normalized = re.sub(r"\s+", " ", text.strip().lower())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
