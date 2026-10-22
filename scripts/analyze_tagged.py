#!/usr/bin/env python3
"""Sensitivity analysis: re-run the rule engine with GitHub-arm files bucketed
by source type (production / example / fixture), using the same rule functions
as analyze.py so numbers are directly comparable to stats_v2.json.

Tagging heuristics (filename encodes <owner>_<repo>__<original path>):
- fixture: kubescape/regolibrary (control test resources), or any path segment
  in FIXTURE_SEGMENTS (test trees, testdata, e2e assets).
- example: known sample/book/tutorial repos, or any path segment in
  EXAMPLE_SEGMENTS (examples, samples, demo, docs, tutorials).
- production: everything else (operator/project manifests as shipped).
Precedence: fixture > example > production. Helm arm is kept whole
("rendered-chart defaults" is its own category, analyzed separately).

Outputs: results/stats_tagged.json, results/file_tags.json
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from analyze import (DEPRECATED_APIS, ROOT, as_list, container_findings,
                     pod_findings, pod_specs)

FIXTURE_REPOS = {"kubescape/regolibrary"}
FIXTURE_SEGMENTS = {"test", "tests", "testdata", "test-data", "fixtures",
                    "fixture", "e2e"}
EXAMPLE_REPOS = {
    "kubernetes/examples",
    "argoproj/argocd-example-apps",
    "GoogleCloudPlatform/microservices-demo",
    "GoogleCloudPlatform/bank-of-anthos",
    "MasayaAoyama/kubernetes-perfect-guide",
    "isovalent/cilium-up-and-running",
    "pavan-kumar-99/medium-manifests",
    "helm/charts",
}
EXAMPLE_SEGMENTS = {"examples", "example", "samples", "sample", "demo",
                    "demos", "docs", "getting-started", "tutorial", "tutorials"}


def tag_of(filename):
    head, _, rest = filename.partition("__")
    owner, _, repo = head.partition("_")
    repo_key = f"{owner}/{repo}"
    segments = [s.lower() for s in rest.split("__")]
    if repo_key in FIXTURE_REPOS or any(s in FIXTURE_SEGMENTS for s in segments):
        return "fixture"
    if repo_key in EXAMPLE_REPOS or any(s in EXAMPLE_SEGMENTS for s in segments):
        return "example"
    return "production"


def main():
    groups = {}       # group -> Counter
    rule_counts = {}  # group -> Counter
    rule_workloads = {}  # group -> defaultdict(set)
    file_tags = {}

    def bucket(group):
        if group not in groups:
            groups[group] = Counter()
            rule_counts[group] = Counter()
            rule_workloads[group] = defaultdict(set)
        return groups[group], rule_counts[group], rule_workloads[group]

    for arm in ("helm", "github"):
        arm_dir = ROOT / "corpus" / arm
        files = sorted(arm_dir.glob("*.yaml")) + sorted(arm_dir.glob("*.yml"))
        for f in files:
            group = arm if arm == "helm" else f"github_{tag_of(f.name)}"
            if arm == "github":
                file_tags[f"github/{f.name}"] = tag_of(f.name)
            s, rc, rw = bucket(group)
            s["files"] += 1
            try:
                docs = list(yaml.safe_load_all(f.read_text(errors="ignore")))
            except Exception:  # noqa: BLE001
                s["files_unparseable"] += 1
                continue
            for doc in docs:
                if not isinstance(doc, dict) or not doc.get("kind"):
                    continue
                s["docs"] += 1
                kind = doc.get("kind")
                api = str(doc.get("apiVersion", ""))
                src = f"{arm}/{f.name}"
                if api in DEPRECATED_APIS:
                    rc["DEPRECATED_API"] += 1
                    s["docs_deprecated_api"] += 1
                if kind == "Secret":
                    rc["SECRET_COMMITTED"] += 1
                    s["secret_objects"] += 1
                if kind in ("Role", "ClusterRole"):
                    for rule in as_list(doc.get("rules")):
                        if not isinstance(rule, dict):
                            continue
                        if "*" in (rule.get("verbs") or []):
                            rc["RBAC_WILDCARD_VERBS"] += 1
                        if "*" in (rule.get("resources") or []):
                            rc["RBAC_WILDCARD_RESOURCES"] += 1
                if kind in ("RoleBinding", "ClusterRoleBinding"):
                    if ((doc.get("roleRef") or {}).get("name")) == "cluster-admin":
                        rc["RBAC_CLUSTER_ADMIN_BINDING"] += 1
                for wkind, wname, spec in pod_specs(doc):
                    s["workloads"] += 1
                    pod_sc = spec.get("securityContext") or {}
                    wl_key = f"{src}:{wkind}/{wname}"
                    for rule in pod_findings(spec):
                        rc[rule] += 1
                        rw[rule].add(wl_key)
                    containers = as_list(spec.get("containers")) + as_list(spec.get("initContainers"))
                    for c in containers:
                        if not isinstance(c, dict):
                            continue
                        s["containers"] += 1
                        for rule in container_findings(c, pod_sc, wkind):
                            rc[rule] += 1
                            rw[rule].add(wl_key)

    stats = {}
    for group, s in groups.items():
        denom_c = max(s["containers"], 1)
        denom_w = max(s["workloads"], 1)
        rc, rw = rule_counts[group], rule_workloads[group]
        stats[group] = {
            **dict(s),
            "rules": {
                r: {"findings": rc[r],
                    "pct_containers": round(100 * rc[r] / denom_c, 1),
                    "workloads_affected": len(rw[r]),
                    "pct_workloads": round(100 * len(rw[r]) / denom_w, 1)}
                for r in sorted(rc)
            },
        }
        print(f"[{group}] files={s['files']} docs={s['docs']} workloads={s['workloads']} "
              f"containers={s['containers']} findings={sum(rc.values())}")

    (ROOT / "results" / "stats_tagged.json").write_text(json.dumps(stats, indent=2))
    (ROOT / "results" / "file_tags.json").write_text(json.dumps(file_tags, indent=2))
    print("\nWrote results/stats_tagged.json and results/file_tags.json")


if __name__ == "__main__":
    main()
