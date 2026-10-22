#!/usr/bin/env python3
"""Build the manual-validation labeling sample from the v2 findings.

Design (logged in LAB_NOTEBOOK.md):
- Universe: results/findings_v2.jsonl (28,109 findings), each joined to its
  source tag from results/file_tags.json (helm = rendered-chart).
- Take ALL findings for the rare, high-severity rules (privileged containers,
  cluster-admin bindings) — these carry the paper's strongest claims.
- For every other rule, draw up to 14 findings, stratified across source
  groups (helm / production / example / fixture) with >=2 per present group.
- Fixed RNG seed (42) for reproducibility; rows shuffled into random order so
  labeling is not rule-clustered.
Output: results/labeling_sample_v2.csv with blank label columns for the
human pass (TP / FP / unsure + notes). See results/labeling_protocol.md.
"""
import csv
import json
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAKE_ALL = {"SEC_PRIVILEGED", "RBAC_CLUSTER_ADMIN_BINDING"}
PER_RULE = 14
MIN_PER_GROUP = 2
SEED = 42


def main():
    tags = json.loads((ROOT / "results" / "file_tags.json").read_text())
    findings = [json.loads(l) for l in (ROOT / "results" / "findings_v2.jsonl").read_text().splitlines() if l.strip()]

    def group_of(f):
        if f["arm"] == "helm":
            return "helm"
        return "github_" + tags.get(f["source"], "production")

    by_rule = defaultdict(list)
    for f in findings:
        f["_group"] = group_of(f)
        by_rule[f["rule"]].append(f)

    rng = random.Random(SEED)
    sample = []
    for rule, rows in sorted(by_rule.items()):
        if rule in TAKE_ALL:
            sample.extend(rows)
            continue
        groups = defaultdict(list)
        for r in rows:
            groups[r["_group"]].append(r)
        picked = []
        # guarantee a floor per present group, then fill proportionally
        for g, grows in sorted(groups.items()):
            rng.shuffle(grows)
            picked.extend(grows[:MIN_PER_GROUP])
        rest = [r for g, grows in groups.items() for r in grows[MIN_PER_GROUP:]]
        rng.shuffle(rest)
        picked.extend(rest[: max(0, PER_RULE - len(picked))])
        sample.extend(picked[:PER_RULE])

    rng.shuffle(sample)
    # ~10% duplicated under new IDs for inter-rater agreement (Cohen's kappa);
    # duplicates are indistinguishable from originals in the CSV.
    dupes = rng.sample(sample, k=max(1, len(sample) // 10))
    sample = sample + dupes
    rng.shuffle(sample)
    out = ROOT / "results" / "labeling_sample_v2.csv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sample_id", "arm", "source_group", "source_file", "kind",
                    "name", "container", "rule", "label", "notes"])
        for i, f in enumerate(sample, 1):
            w.writerow([f"K8S-{i:03d}", f["arm"], f["_group"], f["source"],
                        f["kind"], f["name"], f["container"] or "", f["rule"], "", ""])
    from collections import Counter
    print(f"sample: {len(sample)} rows -> {out}")
    print("by rule:", dict(Counter(f['rule'] for f in sample)))
    print("by group:", dict(Counter(f['_group'] for f in sample)))


if __name__ == "__main__":
    main()
