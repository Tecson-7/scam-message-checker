from typing import Literal

from pydantic import BaseModel, Field

from .config import settings


class CheckRequest(BaseModel):
    text: str = Field(min_length=1, max_length=settings.max_message_chars)
    language: Literal["en", "ta", "hi"] = "en"


class Highlight(BaseModel):
    start: int
    end: int
    text: str
    group: str


class Extracted(BaseModel):
    urls: list[str]
    phones: list[str]
    upi_ids: list[str]
    emails: list[str]
    amounts: list[float]


class LinkResult(BaseModel):
    original_url: str
    final_url: str
    redirects: list[str]
    domain: str | None
    safe_browsing_hit: bool | None      # None = not checked (no API key / API error)
    threat_types: list[str]
    domain_age_days: int | None
    lookalike_of: str | None
    blocked: bool
    error: str | None
    risk: int
    reasons: list[str]


class CheckResponse(BaseModel):
    check_id: int | None                # None when no database is configured
    verdict: Literal["scam", "suspicious", "safe"]
    score: int
    reasons: list[str]
    highlights: list[Highlight]
    extracted: Extracted
    links: list[LinkResult]
    masked_text: str
    message_hash: str
    signals_used: list[str]
