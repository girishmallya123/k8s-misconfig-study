#!/usr/bin/env python3
"""Score the blinded kappa subset: author blind labels vs AI pre-labels.

Usage: python3 scripts/score_kappa.py [path/to/blind_sample.csv]

Reads results/kappa_subset/blind_sample.csv (with blind_label filled in)
and results/prelabels.json; prints raw agreement, Cohen's kappa, the
confusion counts, and every disagreement with the pre-label's reason for
adjudication. Stdlib only.
"""
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results" / "kappa_subset" / "blind_sample.csv"
prelabels = json.load(open(ROOT / "results" / "prelabels.json"))

rows = [r for r in csv.DictReader(open(path)) if r["blind_label"].strip()]
if not rows:
    sys.exit("No blind labels filled in yet.")

pairs = [(r["blind_label"].strip().upper(), prelabels[r["sample_id"]]["label"], r) for r in rows]
n = len(pairs)
agree = sum(1 for a, b, _ in pairs if a == b)

labels = sorted({a for a, _, _ in pairs} | {b for _, b, _ in pairs})
ca, cb = Counter(a for a, _, _ in pairs), Counter(b for _, b, _ in pairs)
pe = sum((ca[l] / n) * (cb[l] / n) for l in labels)
po = agree / n
kappa = (po - pe) / (1 - pe) if pe < 1 else 1.0

print(f"n = {n}   agreement = {agree}/{n} = {po:.1%}   Cohen's kappa = {kappa:.3f}")
print("confusion (author rows x AI cols):")
print("        " + "".join(f"{l:>8}" for l in labels))
for l in labels:
    print(f"{l:>8}" + "".join(f"{sum(1 for a, b, _ in pairs if a == l and b == m):>8}" for m in labels))

dis = [(a, b, r) for a, b, r in pairs if a != b]
if dis:
    print(f"\ndisagreements to adjudicate ({len(dis)}):")
    for a, b, r in dis:
        print(f"  {r['sample_id']} [{r['rule']}] author={a} ai={b} — ai reason: {prelabels[r['sample_id']]['reason']}")
