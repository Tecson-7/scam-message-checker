"""Step 4 - Rule signals: keyword/pattern groups with weights.

Each group counts once (matching "urgent" five times doesn't add five times).
Every match keeps its start/end position so the frontend can highlight it.
Add new patterns as you collect more scam messages in testset/messages.csv.
"""
import re

# "do not share your OTP" must NOT count as an OTP request
_NOT_NEGATED = r"(?<!not )(?<!never )(?<!n't )(?<!dont )"

RULE_GROUPS = {
    "urgency": {
        "weight": 15,
        "reason": "Creates urgency to make you act without thinking",
        "patterns": [
            r"\bimmediately\b", r"\burgent(?:ly)?\b", r"\bact now\b",
            r"\bwithin \d+ ?(?:hours?|hrs?|mins?|minutes?|days?)\b",
            r"\btoday itself\b", r"\bby today\b", r"\btonight\b",
            r"\blast (?:date|chance|day|reminder|warning)\b",
            r"\bexpir(?:es|ed|ing)\b",
            r"\bturant\b", r"तुरंत", r"உடனடியாக",
        ],
    },
    "threat": {
        "weight": 20,
        "reason": "Threatens a penalty (blocked, suspended, legal action)",
        "patterns": [
            r"\b(?:will be|has been|is) (?:blocked|suspended|deactivated|closed|disconnected|frozen)\b",
            r"\bblocked\b", r"\bsuspended\b", r"\bdeactivat(?:e|ed|ion)\b",
            r"\blegal action\b", r"\barrest(?:ed)?\b", r"\bpenalty\b", r"\bfir\b",
            r"\bband ho jayega\b", r"बंद हो",
        ],
    },
    "kyc": {
        "weight": 25,
        "reason": "Asks for KYC/PAN/Aadhaar update — banks don't do this over SMS",
        "patterns": [
            r"\b(?:e-?)?kyc\b",
            r"\bpan(?: card)? (?:update|link|verif\w*)\b",
            r"\baadha+r (?:update|link|verif\w*)\b",
            r"\bupdate (?:your )?(?:pan|kyc|aadha+r|details|account)\b",
        ],
    },
    "otp_request": {
        "weight": 30,
        "reason": "Asks you to share an OTP, PIN or CVV — never share these",
        "patterns": [
            _NOT_NEGATED + r"\b(?:share|send|tell|forward|provide|enter)\b[^.\n]{0,30}\b(?:otp|pin|cvv|password)\b",
        ],
    },
    "payment": {
        "weight": 20,
        "reason": "Asks you to pay money",
        "patterns": [
            r"\bpay (?:₹|rs\.?|inr)", r"\bpay now\b",
            r"\b(?:processing|registration|delivery|customs|clearance) (?:fee|charge)s?\b",
            r"\bsend money\b", r"\btransfer (?:₹|rs\.?|inr)",
        ],
    },
    "prize": {
        "weight": 20,
        "reason": "Offers a prize or reward that sounds too good to be true",
        "patterns": [
            r"\byou (?:have )?won\b", r"\blottery\b", r"\blucky draw\b",
            r"\bcongratulations\b", r"\bprize\b", r"\bjackpot\b",
            r"\breward points? (?:will )?(?:expir\w*|redeem\w*)\b", r"\binaam\b", r"इनाम",
        ],
    },
    "job_offer": {
        "weight": 25,
        "reason": "Easy-money job offer (a common task/job scam)",
        "patterns": [
            r"\bwork from home\b", r"\bpart[- ]time (?:job|work)\b",
            r"\bearn (?:₹|rs\.?|inr)\s?\d", r"\bdaily (?:income|earning|salary|payment)\b",
            r"\blik(?:e|ing) (?:youtube )?(?:videos|posts)\b",
        ],
    },
    "parcel": {
        "weight": 25,
        "reason": "Says your parcel is held/undelivered — a common courier scam",
        "patterns": [
            r"\b(?:parcel|package|shipment|courier)\b[^.\n]{0,25}\b(?:held|on hold|returned|undelivered|could not be delivered)\b",
            r"\bincomplete (?:address|details)\b",
            r"\bre-?delivery\b",
        ],
    },
    "electricity": {
        "weight": 25,
        "reason": "Threatens electricity disconnection — a common EB bill scam",
        "patterns": [
            r"\b(?:electricity|power|eb)(?: connection)?(?: will be)? (?:disconnect\w*|cut)\b",
            r"\b(?:previous|last) month(?:'s)? bill (?:was |has )?not (?:been )?updated\b",
            r"\belectricity (?:officer|department)\b",
        ],
    },
    "contact_push": {
        "weight": 10,
        "reason": "Pushes you to click a link or call an unknown number",
        "patterns": [
            r"\bclick (?:here|on the link|the link|below|now)\b",
            r"\bcall (?:this|our|the)? ?(?:number|officer|executive|helpline)\b",
            r"\bcontact (?:this|our) (?:number|officer)\b",
            r"\bwhats ?app (?:us|me|on)\b",
        ],
    },
}

# Signals that are much stronger together
COMBOS = [
    ({"has_link"}, {"kyc", "threat", "urgency", "electricity", "prize", "parcel"}, 20,
     "Has a link together with pressure tactics"),
    ({"has_phone"}, {"electricity", "threat", "kyc"}, 15,
     "Asks you to call a number together with a threat"),
    ({"has_phone"}, {"job_offer", "prize"}, 15,
     "Asks you to call/WhatsApp a number for an easy-money offer"),
    ({"has_upi"}, {"payment", "prize", "job_offer"}, 10,
     "Gives a UPI ID together with a payment request"),
]

_COMPILED = {
    name: [re.compile(p, re.IGNORECASE) for p in g["patterns"]]
    for name, g in RULE_GROUPS.items()
}


def score_rules(text: str, extracted: dict) -> dict:
    """Return {score, groups, matches, reasons}."""
    matches = []
    hit_groups = set()

    for name, patterns in _COMPILED.items():
        for pat in patterns:
            for m in pat.finditer(text):
                hit_groups.add(name)
                matches.append({
                    "start": m.start(), "end": m.end(),
                    "text": m.group(0), "group": name,
                })

    score = sum(RULE_GROUPS[g]["weight"] for g in hit_groups)
    reasons = [RULE_GROUPS[g]["reason"] for g in sorted(hit_groups, key=lambda g: -RULE_GROUPS[g]["weight"])]

    features = set()
    if extracted.get("urls"):
        features.add("has_link")
    if extracted.get("phones"):
        features.add("has_phone")
    if extracted.get("upi_ids"):
        features.add("has_upi")

    for needs, any_of, bonus, reason in COMBOS:
        if needs <= features and hit_groups & any_of:
            score += bonus
            reasons.append(reason)

    matches = _drop_nested(matches)
    return {
        "score": min(score, 100),
        "groups": sorted(hit_groups),
        "matches": matches,
        "reasons": reasons,
    }


def _drop_nested(matches: list[dict]) -> list[dict]:
    """Keep the longest span when matches overlap (e.g. 'will be blocked' vs 'blocked')."""
    matches.sort(key=lambda m: (m["start"], -(m["end"] - m["start"])))
    kept = []
    for m in matches:
        if kept and m["start"] < kept[-1]["end"]:
            continue
        kept.append(m)
    return kept
