#!/usr/bin/env python3
"""Build the methods fix kit (2026-10-22).

Outputs:
  results/divergence_list.csv      rows where protocol v1 (exploitability)
                                    and v2 (definitional) can disagree
  results/kappa_subset/blind_sample.csv   blinded 30-row human-vs-AI subset
  results/kappa_subset/packets.jsonl      evidence packets for those rows

Deterministic (fixed seeds). Stdlib only.
"""
import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"

sample = list(csv.DictReader(open(RES / "labeling_sample_v2.csv")))
prelabels = json.load(open(RES / "prelabels.json"))
packets = {p["sample_id"]: p for p in
           (json.loads(l) for l in open(RES / "labeling_packets.jsonl"))}

by_id = {r["sample_id"]: r for r in sample}


def container_facts(pid):
    """Best-effort escalation-path signals from a row's evidence packet."""
    pkt = packets.get(pid, {})
    nonroot, has_caps = False, False
    for c in pkt.get("containers") or []:
        sc = (c.get("securityContext") or {}) if isinstance(c, dict) else {}
        rau = sc.get("runAsUser")
        if isinstance(rau, int) and rau > 0:
            nonroot = True
        if sc.get("runAsNonRoot") is True:
            nonroot = True
        caps = ((sc.get("capabilities") or {}).get("add") or [])
        if caps:
            has_caps = True
    pod_sc = pkt.get("pod_sc") or {}
    if isinstance(pod_sc.get("runAsUser"), int) and pod_sc.get("runAsUser") > 0:
        nonroot = True
    if pod_sc.get("runAsNonRoot") is True:
        nonroot = True
    return nonroot, has_caps


# ---------------------------------------------------------------- divergence
div_rows = []
for r in sample:
    pid = r["sample_id"]
    pre = prelabels.get(pid, {}).get("label")
    rule = r["rule"]
    if rule == "IMG_NO_DIGEST" and pre == "TP":
        div_rows.append((pid, rule, r["arm"], r["source_group"], pre, "A_img_digest_tier",
                         "v1: explicit tag without digest = standard practice; record as hardening gap, not misconfiguration",
                         "Re-tier as TP-hardening (not TP-misconfiguration) under v3"))
    elif rule.startswith(("RES_", "REL_")) and pre == "TP" and (
            r["source_group"].endswith(("example", "fixture"))):
        div_rows.append((pid, rule, r["arm"], r["source_group"], pre, "B_context_source",
                         "v1: example/fixture/one-shot manifests are FP for resource and probe rules",
                         "Flip to FP under v3 (context rule), or justify in notes"))
    elif rule in ("SEC_APE_NOT_DISABLED", "SEC_ROOT_NOT_PREVENTED") and pre == "TP":
        nonroot, has_caps = container_facts(pid)
        if nonroot and not has_caps:
            div_rows.append((pid, rule, r["arm"], r["source_group"], pre, "C_escalation_path",
                             "v1: non-root + no added caps = escalation path absent (not-exploitable FP)",
                             "Flip to FP under v3 unless packet shows root/caps evidence"))
        else:
            div_rows.append((pid, rule, r["arm"], r["source_group"], pre, "C_escalation_path_check",
                             "v1: TP requires a real escalation path (root, added caps, or writable rootfs w/ setuid risk)",
                             "Verify escalation path in packet during pass; keep TP only if present"))
    elif pre == "unsure":
        div_rows.append((pid, rule, r["arm"], r["source_group"], pre, "D_evidence_absent",
                         "Both protocols: unsure = cannot tell from the manifest alone",
                         "Resolve by rendering (kustomize) or exclude + disclose count under v3"))

with open(RES / "divergence_list.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sample_id", "rule", "arm", "source_group", "prelabel",
                "divergence_class", "v1_test", "v3_action"])
    w.writerows(div_rows)

print("divergence rows:", len(div_rows), Counter(d[5] for d in div_rows))

# ---------------------------------------------------------------- kappa subset
groups = defaultdict(list)
for r in sample:
    key = (r["source_file"], r["kind"], r["name"], r["container"], r["rule"])
    groups[key].append(r["sample_id"])
pool = [r for r in sample
        if len(groups[(r["source_file"], r["kind"], r["name"], r["container"], r["rule"])]) == 1
        and prelabels.get(r["sample_id"], {}).get("label") in ("TP", "FP")]
print("unique-content TP/FP pool:", len(pool))

rng = random.Random(20261022)
by_rule = defaultdict(list)
for r in pool:
    by_rule[r["rule"]].append(r)
for v in by_rule.values():
    rng.shuffle(v)

chosen = []
for rule, rows in sorted(by_rule.items()):          # 1 per rule first
    chosen.append(rows.pop())
remaining = [r for rows in by_rule.values() for r in rows]
rng.shuffle(remaining)
chosen += remaining[:30 - len(chosen)]
chosen = chosen[:30]
chosen_ids = sorted(c["sample_id"] for c in chosen)
print("kappa subset:", len(chosen_ids), Counter(c["rule"] for c in chosen))

kdir = RES / "kappa_subset"
kdir.mkdir(exist_ok=True)
with open(kdir / "blind_sample.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sample_id", "arm", "source_group", "source_file", "kind",
                "name", "container", "rule", "blind_label", "blind_notes"])
    for pid in chosen_ids:
        r = by_id[pid]
        w.writerow([pid, r["arm"], r["source_group"], r["source_file"], r["kind"],
                    r["name"], r["container"], r["rule"], "", ""])
with open(kdir / "packets.jsonl", "w") as f:
    for pid in chosen_ids:
        if pid in packets:
            f.write(json.dumps(packets[pid]) + "\n")
print("wrote kappa subset for", len(chosen_ids), "rows")
