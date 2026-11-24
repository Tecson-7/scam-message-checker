"""Repository tests on an in-memory SQLite DB (same code runs on Neon Postgres)."""
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.models import Base, Check, Link
from app.repository import get_cached_links, save_check, save_link_cache

LINK = {"original_url": "bit.ly/x", "final_url": "https://sbi-kyc.xyz", "domain": "sbi-kyc.xyz",
        "domain_age_days": 3, "safe_browsing_hit": False, "lookalike_of": "SBI", "risk": 85}
RESULT = {"verdict": "scam", "score": 88, "reasons": ["r1"]}


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, expire_on_commit=False)() as s:
        yield s


def _save(session, h="abc"):
    return save_check(session, message_hash=h, masked_text="masked", language="en",
                      result=RESULT, tactics=["kyc"], links=[LINK])


def test_same_message_is_deduplicated(session):
    first = _save(session)
    second = _save(session)
    assert first == second
    check = session.get(Check, first)
    assert check.times_checked == 2
    assert session.scalar(select(func.count()).select_from(Link)) == 1   # links replaced, not doubled


def test_different_messages_get_new_rows(session):
    assert _save(session, "a") != _save(session, "b")


def test_link_cache_roundtrip(session):
    save_link_cache(session, [LINK])
    assert get_cached_links(session, ["bit.ly/x", "other.com"]) == {"bit.ly/x": LINK}


def test_llm_result_is_cached_per_language(session):
    from app.repository import get_cached_llm
    llm = {"category": "kyc_bank", "is_scam_likelihood": 90, "tactics": [], "red_flag_phrases": [],
           "explanation": "x", "impersonated_entity": "SBI"}
    save_check(session, message_hash="h", masked_text="m", language="ta",
               result=RESULT, tactics=[], links=[], llm=llm)
    assert get_cached_llm(session, "h", "ta") == llm
    assert get_cached_llm(session, "h", "en") is None
