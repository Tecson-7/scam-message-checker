import logging

from fastapi import APIRouter
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from .. import db
from ..repository import get_cached_links, save_check, save_link_cache
from ..schemas import CheckRequest, CheckResponse
from ..services.extract import extract
from ..services.links import check_links
from ..services.privacy import mask_text, message_hash
from ..services.rules import score_rules
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


async def run_pipeline(text: str, language: str = "en", use_links: bool = True, save: bool = True) -> dict:
    use_db = db.ready

    # 1-2. Extract + rules (fast, offline)
    extracted = extract(text)
    rules = score_rules(text, extracted)

    # 3. Links (cached for 24h in Postgres)
    if use_links:
        urls = extracted["urls"]
        cached = await _safe_db({}, get_cached_links, urls) if use_db and urls else {}
        link_report = await check_links(urls, cached=cached)
        if use_db and link_report["fresh"]:
            await _safe_db(None, save_link_cache, link_report["fresh"])
    else:
        link_report = await check_links([])

    # TODO Step 8: llm = classify(text, link_report["links"], language)

    # 4. Combine
    result = combine(
        rule_score=rules["score"],
        link_risk=link_report["link_risk"],
        safe_browsing_hit=link_report["safe_browsing_hit"],
    )
    reasons = link_report["reasons"] + rules["reasons"] or ["No common scam patterns found"]
    hash_ = message_hash(text)
    masked = mask_text(text)

    # 5. Save (masked text only)
    check_id = None
    if use_db and save:
        check_id = await _safe_db(
            None, save_check,
            message_hash=hash_, masked_text=masked, language=language,
            result={**result, "reasons": reasons}, tactics=rules["groups"], links=link_report["links"],
        )

    return {
        **result,
        "check_id": check_id,
        "reasons": reasons,
        "highlights": rules["matches"],
        "extracted": extracted,
        "links": link_report["links"],
        "masked_text": masked,
        "message_hash": hash_,
    }


@router.post("/check", response_model=CheckResponse)
async def check_message(req: CheckRequest):
    return await run_pipeline(req.text, req.language)
