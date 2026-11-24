"""Step 9 - Combine rule, link and LLM scores into one verdict.

Missing signals are dropped and the remaining weights re-normalised, so a
message with no links isn't dragged down by a link_risk of 0.

When EVERY signal says "risky" (>= 40), take the strongest one instead of the
average - two red flags must never score lower than one. When signals disagree
(e.g. keywords say scam, LLM says legit) the weighted average decides.
Right now only rules are wired in; links and LLM plug in later.
"""

WEIGHTS = {"llm": 0.40, "links": 0.35, "rules": 0.25}
SCAM_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40


def combine(rule_score: float, llm_score: float | None = None,
            link_risk: float | None = None, safe_browsing_hit: bool = False) -> dict:
    parts = {"rules": rule_score}
    if llm_score is not None:
        parts["llm"] = llm_score
    if link_risk is not None:          # None = no links; 0 = links checked and clean
        parts["links"] = link_risk

    total_weight = sum(WEIGHTS[k] for k in parts)
    score = sum(WEIGHTS[k] * v for k, v in parts.items()) / total_weight
    if all(v >= SUSPICIOUS_THRESHOLD for v in parts.values()):
        score = max(score, max(parts.values()))

    if safe_browsing_hit:
        score = max(score, 90)         # hard override

    score = round(score)
    if score >= SCAM_THRESHOLD:
        verdict = "scam"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {"score": score, "verdict": verdict, "signals_used": sorted(parts)}
