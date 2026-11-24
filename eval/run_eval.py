"""Step 11 - Evaluate the checker on testset/messages.csv.

Run from the project root:
    python eval/run_eval.py                 # rules only (offline, instant)
    python eval/run_eval.py --links         # + rules+links (real link checks)
    python eval/run_eval.py --links --llm   # + LLM only, combined (uses Gemini quota)

"Flagged" = suspicious or scam (score >= 40). Nothing is saved to the database.
Gemini is called once per message; the LLM-only and combined rows reuse that answer.
"""
import asyncio
import csv
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT / "backend")                    # so .env is picked up
sys.path.insert(0, str(ROOT / "backend"))

from app.routers.check import run_pipeline          # noqa: E402
from app.services.scorer import SUSPICIOUS_THRESHOLD  # noqa: E402

GEMINI_DELAY_SECONDS = 4      # stay under free-tier requests-per-minute limits


def metrics(preds, rows):
    tp = fp = fn = tn = 0
    for flagged, row in zip(preds, rows):
        scam = row["label"] == "scam"
        tp += flagged and scam
        fp += flagged and not scam
        fn += (not flagged) and scam
        tn += (not flagged) and not scam
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    return precision, recall, fpr


async def collect(rows, use_links, use_llm):
    results = []
    for i, row in enumerate(rows):
        results.append(await run_pipeline(row["text"], use_links=use_links, use_llm=use_llm, save=False))
        if use_llm and i < len(rows) - 1:
            time.sleep(GEMINI_DELAY_SECONDS)
    return results


def main():
    rows = list(csv.DictReader(open(ROOT / "testset" / "messages.csv", encoding="utf-8")))
    use_links, use_llm = "--links" in sys.argv, "--llm" in sys.argv

    table = []
    rules = asyncio.run(collect(rows, False, False))
    table.append(("Rules only", [r["verdict"] != "safe" for r in rules], rules))

    if use_links:
        rl = asyncio.run(collect(rows, True, False))
        table.append(("Rules + links", [r["verdict"] != "safe" for r in rl], rl))

    if use_llm:
        print(f"Calling Gemini for {len(rows)} messages (~{len(rows) * GEMINI_DELAY_SECONDS}s)...")
        full = asyncio.run(collect(rows, use_links, True))
        missing = sum(r["llm_likelihood"] is None for r in full)
        if missing:
            print(f"⚠ Gemini gave no answer for {missing} messages - check the warnings above")
        llm_only = [(r["llm_likelihood"] or 0) >= SUSPICIOUS_THRESHOLD for r in full]
        table.append(("LLM only", llm_only, full))
        table.append(("Combined", [r["verdict"] != "safe" for r in full], full))

    n_scam = sum(r["label"] == "scam" for r in rows)
    print(f"\nMessages: {len(rows)}  (scam={n_scam}, legit={len(rows) - n_scam})\n")
    print("| Mode | Precision | Recall | False-positive rate |")
    print("|---|---|---|---|")
    for name, preds, _ in table:
        p, r, f = metrics(preds, rows)
        print(f"| {name} | {p:.0%} | {r:.0%} | {f:.0%} |")

    name, preds, results = table[-1]
    for flagged, row, res in zip(preds, rows, results):
        if flagged != (row["label"] == "scam"):
            kind = "FALSE POSITIVE" if flagged else "MISSED SCAM"
            print(f"\n[{name}] {kind} (id {row['id']}, score {res['score']}): {row['text'][:90]}")


if __name__ == "__main__":
    main()
