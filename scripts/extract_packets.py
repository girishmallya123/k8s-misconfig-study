#!/usr/bin/env python3
"""Extract a compact evidence packet for every labeling-sample row.

For each row of results/labeling_sample_v2.csv, find the flagged object in its
corpus file and emit only the fields the labeling judgment depends on:
security contexts, resources, probes, image refs, the service account's own
automount setting, legacy seccomp annotations, secret value previews (for
placeholder detection), and RBAC rules/refs.

Output: results/labeling_packets.jsonl (one JSON object per sample row).
"""
import base64
import csv
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from analyze import ROOT, as_list, pod_specs

SAMPLE = ROOT / "results" / "labeling_sample_v2.csv"
OUT = ROOT / "results" / "labeling_packets.jsonl"

_cache = {}


def load_docs(src):
    if src not in _cache:
        p = ROOT / "corpus" / src
        try:
            docs = [d for d in yaml.safe_load_all(p.read_text(errors="ignore"))
                    if isinstance(d, dict) and d.get("kind")]
        except Exception:  # noqa: BLE001
            docs = []
        _cache[src] = docs
    return _cache[src]


def trunc(v, n=48):
    s = str(v)
    return s if len(s) <= n else s[:n] + "…"


def secret_preview(doc):
    out = {}
    for k, v in (doc.get("data") or {}).items():
        try:
            dec = base64.b64decode(str(v)).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            dec = str(v)
        out[k] = trunc(dec, 40)
    for k, v in (doc.get("stringData") or {}).items():
        out[k] = trunc(v, 40)
    return {"type": doc.get("type"), "values": out}


def workload_packet(doc, wkind, wname, spec, target_container, docs):
    meta = (doc.get("metadata") or {})
    tmpl_meta = ((doc.get("spec") or {}).get("template") or {}).get("metadata") or {}
    anns = {k: v for k, v in (tmpl_meta.get("annotations") or {}).items()
            if "seccomp" in k or "apparmor" in k}
    sa_name = spec.get("serviceAccountName") or spec.get("serviceAccount")
    sa_automount = None
    if sa_name:
        for d in docs:
            if d.get("kind") == "ServiceAccount" and (d.get("metadata") or {}).get("name") == sa_name:
                sa_automount = d.get("automountServiceAccountToken")
                break
    containers = []
    all_c = [c for c in as_list(spec.get("containers")) + as_list(spec.get("initContainers"))
             if isinstance(c, dict)]
    if target_container:
        all_c = [c for c in all_c if c.get("name") == target_container] or all_c[:1]
    for c in all_c[:4]:
        env = [{"name": e.get("name"), "value": trunc(e.get("value"), 40)}
               for e in as_list(c.get("env")) if isinstance(e, dict) and "value" in e]
        containers.append({
            "name": c.get("name"), "image": c.get("image"),
            "sc": c.get("securityContext"), "resources": c.get("resources"),
            "probes": [p for p in ("livenessProbe", "readinessProbe", "startupProbe") if c.get(p)],
            "env_values": env,
        })
        if target_container and c.get("name") == target_container:
            break
    return {
        "ns": meta.get("namespace"), "sa": sa_name, "sa_automount": sa_automount,
        "pod_automount": spec.get("automountServiceAccountToken"),
        "annotations": anns, "pod_sc": spec.get("securityContext"),
        "host": {k: spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC") if spec.get(k)},
        "containers": containers,
    }


def main():
    rows = list(csv.DictReader(SAMPLE.open()))
    packets = []
    missing = 0
    for r in rows:
        docs = load_docs(r["source_file"])
        pkt = {"sample_id": r["sample_id"], "rule": r["rule"], "group": r["source_group"],
               "file": r["source_file"], "kind": r["kind"], "name": r["name"],
               "container": r["container"] or None}
        found = False
        # Pass 1: workload match (most rules are workload/container-level).
        for doc in docs:
            for wkind, wname, spec in pod_specs(doc):
                if wkind == r["kind"] and wname == r["name"]:
                    pkt.update(workload_packet(doc, wkind, wname, spec, r["container"] or None, docs))
                    found = True
                    break
            if found:
                break
        # Pass 2: document-level kinds (Secret / RBAC).
        if not found:
            for doc in docs:
                kind = doc.get("kind")
                name = (doc.get("metadata") or {}).get("name")
                if name != r["name"]:
                    continue
                if kind == "Secret":
                    pkt["secret"] = secret_preview(doc)
                    found = True
                    break
                if kind in ("Role", "ClusterRole"):
                    pkt["rbac_rules"] = doc.get("rules")
                    found = True
                    break
                if kind in ("RoleBinding", "ClusterRoleBinding"):
                    pkt["roleRef"] = doc.get("roleRef")
                    pkt["subjects"] = doc.get("subjects")
                    found = True
                    break
        if not found:
            missing += 1
            pkt["not_found"] = True
        packets.append(pkt)
    OUT.write_text("\n".join(json.dumps(p) for p in packets) + "\n")
    print(f"packets: {len(packets)}, not_found: {missing} -> {OUT}")


if __name__ == "__main__":
    main()
