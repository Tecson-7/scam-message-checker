from app.services.extract import extract
from app.services.privacy import mask_text, message_hash
from app.services.rules import score_rules


def _score(text):
    return score_rules(text, extract(text))


def test_kyc_scam_scores_high():
    r = _score("Dear customer your SBI account will be blocked today. "
               "Update KYC immediately: sbi-kyc.xyz")
    assert r["score"] >= 70
    assert {"kyc", "threat", "urgency"} <= set(r["groups"])


def test_legit_otp_sms_is_not_an_otp_request():
    r = _score("482913 is your OTP for txn of Rs.500. Do not share OTP with anyone. -SBI")
    assert "otp_request" not in r["groups"]
    assert r["score"] < 40


def test_otp_request_is_caught():
    assert "otp_request" in _score("Please share the OTP you received to verify")["groups"]


def test_highlight_positions_match_text():
    text = "Your power will be disconnected tonight"
    for m in _score(text)["matches"]:
        assert text[m["start"]:m["end"]] == m["text"]


def test_masking():
    masked = mask_text("Dear Ravi, call 9876543210, a/c 123456789012, pay ravi.k@okaxis")
    assert "Ravi" not in masked
    assert "9876543210" not in masked and "98XXXXXX10" in masked
    assert "XXXX9012" in masked
    assert "ra***@okaxis" in masked


def test_hash_ignores_case_and_spacing():
    assert message_hash("Hello   World ") == message_hash("hello world")


def test_highlights_do_not_overlap():
    ms = _score("Your account will be blocked. Update KYC now")["matches"]
    assert all(a["end"] <= b["start"] for a, b in zip(ms, ms[1:]))
