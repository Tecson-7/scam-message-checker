from app.services.privacy import mask_text
from app.services.scorer import combine


def test_two_red_flags_never_score_lower_than_one():
    rules_only = combine(rule_score=80)
    with_bad_link = combine(rule_score=80, link_risk=60)
    assert with_bad_link["score"] >= rules_only["score"]
    assert with_bad_link["verdict"] == "scam"


def test_clean_link_lowers_keyword_only_suspicion():
    assert combine(rule_score=80, link_risk=0)["score"] < 80


def test_no_links_ignores_link_weight():
    assert combine(rule_score=50)["score"] == 50


def test_safe_browsing_override():
    assert combine(rule_score=0, link_risk=100, safe_browsing_hit=True)["score"] >= 90


def test_generic_greeting_is_not_masked():
    assert mask_text("Dear customer, hi Ravi") == "Dear customer, hi [name]"
    assert mask_text("Dear Customer") == "Dear Customer"
