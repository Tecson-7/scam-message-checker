"""Step 6 - All database reads/writes in one place."""
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Check, Link, LinkCache, utcnow

LINK_CACHE_HOURS = 24


def get_cached_llm(session: Session, message_hash: str, language: str) -> dict | None:
    """Same message + language checked before -> reuse Gemini's answer (saves quota)."""
    return session.scalar(
        select(Check.llm_result).where(Check.message_hash == message_hash, Check.language == language)
    )


def save_check(session: Session, *, message_hash: str, masked_text: str, language: str,
               result: dict, tactics: list, links: list[dict], llm: dict | None = None) -> int:
    """Insert a check, or update the existing one if the same message was checked before."""
    check = session.scalar(
        select(Check).where(Check.message_hash == message_hash, Check.language == language)
    )
    if check is None:
        check = Check(message_hash=message_hash, language=language, times_checked=1)
        session.add(check)
    else:
        check.times_checked += 1
        check.links.clear()            # replace with the latest link results

    check.masked_text = masked_text
    check.verdict = result["verdict"]
    check.score = result["score"]
    check.reasons = result["reasons"]
    check.tactics = tactics
    if llm is not None:
        check.llm_result = llm
        check.category = llm["category"]

    for l in links:
        check.links.append(Link(
            original_url=l["original_url"], final_url=l["final_url"], domain=l["domain"],
            domain_age_days=l["domain_age_days"], safe_browsing_hit=l["safe_browsing_hit"],
            lookalike_of=l["lookalike_of"], risk=l["risk"],
        ))

    session.commit()
    return check.id


def get_cached_links(session: Session, urls: list[str]) -> dict[str, dict]:
    if not urls:
        return {}
    cutoff = utcnow() - timedelta(hours=LINK_CACHE_HOURS)
    rows = session.scalars(
        select(LinkCache).where(LinkCache.url.in_(urls), LinkCache.checked_at >= cutoff)
    )
    return {row.url: row.result for row in rows}


def save_link_cache(session: Session, results: list[dict]) -> None:
    for r in results:
        session.merge(LinkCache(url=r["original_url"], result=r, checked_at=utcnow()))
    session.commit()
