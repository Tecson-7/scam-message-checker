"""Step 11 - Evaluate the checker on testset/messages.csv.

Run from the project root:
    python eval/run_eval.py            # rules only (offline, instant)
    python eval/run_eval.py --links    # also rules + links (real network calls, uses your .env keys)

"Flagged" = suspicious or scam (score >= 40). Nothing is saved to the database.
"""
import asyncio
import csv
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT / "backend")                    # so .env is picked up
sys.path.insert(0, str(ROOT / "backend"))

from app.routers.check import run_pipeline  # noqa: E402


async def evaluate(rows, use_links):
    tp = fp = fn = tn = 0
    mistakes = []
    for row in rows:
        result = await run_pipeline(row["text"], use_links=use_links, save=False)
        flagged = result["verdict"] != "safe"
        is_scam = row["label"] == "scam"
        if flagged and is_scam:
            tp += 1
        elif flagged:
            fp += 1
            mistakes.append(("FALSE POSITIVE", row, result))
        elif is_scam:
            fn += 1
            mistakes.append(("MISSED SCAM", row, result))
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    return precision, recall, fpr, mistakes


def main():
    rows = list(csv.DictReader(open(ROOT / "testset" / "messages.csv", encoding="utf-8")))
    modes = [("Rules only", False)] + ([("Rules + links", True)] if "--links" in sys.argv else [])

    n_scam = sum(r["label"] == "scam" for r in rows)
    print(f"Messages: {len(rows)}  (scam={n_scam}, legit={len(rows) - n_scam})\n")
    print("| Mode | Precision | Recall | False-positive rate |")
    print("|---|---|---|---|")
    all_mistakes = []
    for name, use_links in modes:
        p, r, f, mistakes = asyncio.run(evaluate(rows, use_links))
        print(f"| {name} | {p:.0%} | {r:.0%} | {f:.0%} |")
        all_mistakes += [(name, *m) for m in mistakes]

    for mode, kind, row, result in all_mistakes:
        print(f"\n[{mode}] {kind} (id {row['id']}, score {result['score']}): {row['text'][:90]}")


if __name__ == "__main__":
    main()
