import logging
import re

from fastapi import APIRouter
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from .. import db
from ..repository import get_cached_links, get_cached_llm, save_check, save_link_cache
from ..schemas import CheckRequest, CheckResponse
from ..services.extract import extract
from ..services.links import check_links
from ..services.llm import classify
from ..services.privacy import mask_text, message_hash
from ..services.rules import merge_spans, score_rules
from ..services.scorer import combine

router = APIRouter(prefix="/api")
log = logging.getLogger("uvicorn.error")


def _db_call(fn, *args, **kwargs):
    """Run one repository function in its own session (called in a threadpool)."""
    with db.SessionLocal() as session:
        return fn(session, *args, **kwargs)


async def _safe_db(default, fn, *args, **kwargs):
    """A database problem should never break a check - log it and carry on."""
    try:
        return await run_in_threadpool(_db_call, fn, *args, **kwargs)
    except SQLAlchemyError as e:
        log.warning("Database call %s failed: %s", fn.__name__, e)
        return default


def _phrase_spans(text: str, phrases: list[str]) -> list[dict]:
    """Positions of Gemini's red-flag phrases, for highlighting."""
    spans = []
    for p in phrases:
        for m in re.finditer(re.escape(p), text, re.IGNORECASE):
            spans.append({"start": m.start(), "end": m.end(), "text": m.group(0), "group": "llm"})
    return spans


async def run_pipeline(text: str, language: str = "en", use_links: bool = True,
                       use_llm: bool = True, save: bool = True) -> dict:
    use_db = db.ready
    hash_ = message_hash(text)

    # 1-2. Extract + rules (fast, offline)
    extracted = extract(text)
    rules = score_rules(text, extracted)

    # 3. Links (cached 24h)
    urls = extracted["urls"] if use_links else []
    cached = await _safe_db({}, get_cached_links, urls) if use_db and urls else {}
    link_report = await check_links(urls, cached=cached)
    if use_db and link_report["fresh"]:
        await _safe_db(None, save_link_cache, link_report["fresh"])

    # 4. LLM (cached per message + language, so repeat checks don't use quota)
    llm = None
    if use_llm:
        if use_db:
            llm = await _safe_db(None, get_cached_llm, hash_, language)
        if llm is None:
            llm = await classify(text, link_report["links"], language)

    # 5. Combine
    result = combine(
        rule_score=rules["score"],
        llm_score=llm["is_scam_likelihood"] if llm else None,
        link_risk=link_report["link_risk"],
        safe_browsing_hit=link_report["safe_browsing_hit"],
    )
    reasons = link_report["reasons"] + rules["reasons"] or ["No common scam patterns found"]
    highlights = merge_spans(rules["matches"] + _phrase_spans(text, llm["red_flag_phrases"] if llm else []))
    masked = mask_text(text)

    # 6. Save (masked text only)
    check_id = None
    if use_db and save:
        check_id = await _safe_db(
            None, save_check,
            message_hash=hash_, masked_text=masked, language=language,
            result={**result, "reasons": reasons},
            tactics=(llm["tactics"] if llm else []) or rules["groups"],
            links=link_report["links"], llm=llm,
        )

    return {
        **result,
        "check_id": check_id,
        "category": llm["category"] if llm else None,
        "explanation": llm["explanation"] if llm else None,
        "impersonated_entity": llm["impersonated_entity"] if llm else None,
        "llm_likelihood": llm["is_scam_likelihood"] if llm else None,
        "reasons": reasons,
        "highlights": highlights,
        "extracted": extracted,
        "links": link_report["links"],
        "masked_text": masked,
        "message_hash": hash_,
    }


@router.post("/check", response_model=CheckResponse)
async def check_message(req: CheckRequest):
    return await run_pipeline(req.text, req.language)
