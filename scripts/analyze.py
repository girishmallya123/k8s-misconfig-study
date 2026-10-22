#!/usr/bin/env python3
"""Taxonomy v1 rule engine. Walks corpus/{helm,github}, parses every YAML doc,
extracts pod specs from workload kinds, applies misconfiguration rules, and
writes results/findings.jsonl + results/stats.json.

Rule definitions follow the CIS Kubernetes Benchmark / NSA-CISA hardening
guidance categories. Where a hardening field is absent, Kubernetes defaults
apply (e.g. automountServiceAccountToken defaults true), so absence counts as
a finding and the rule name says so.
"""
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ARMS = ["helm", "github"]

WORKLOAD_TEMPLATE_PATHS = {
    "Deployment": ("spec", "template"),
    "ReplicaSet": ("spec", "template"),
    "StatefulSet": ("spec", "template"),
    "DaemonSet": ("spec", "template"),
    "Job": ("spec", "template"),
    "ReplicationController": ("spec", "template"),
}
LONG_RUNNING = {"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Pod"}

DEPRECATED_APIS = {
    "extensions/v1beta1", "apps/v1beta1", "apps/v1beta2",
    "policy/v1beta1", "networking.k8s.io/v1beta1",
    "admissionregistration.k8s.io/v1beta1", "scheduling.k8s.io/v1beta1",
    "storage.k8s.io/v1beta1", "apiextensions.k8s.io/v1beta1",
    "rbac.authorization.k8s.io/v1alpha1", "rbac.authorization.k8s.io/v1beta1",
    "authentication.k8s.io/v1beta1", "certificates.k8s.io/v1beta1",
    "coordination.k8s.io/v1beta1", "events.k8s.io/v1beta1",
}

SECRET_ENV_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|access[_-]?key)", re.I)


def as_list(x):
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        return list(x.values())
    return []


def pod_specs(doc):
    """Yield (kind, name, podspec) for a document."""
    kind = doc.get("kind")
    meta_name = (doc.get("metadata") or {}).get("name", "?")
    if kind == "Pod":
        yield kind, meta_name, doc.get("spec") or {}
    elif kind in WORKLOAD_TEMPLATE_PATHS:
        node = doc
        for key in WORKLOAD_TEMPLATE_PATHS[kind]:
            node = (node or {}).get(key) or {}
        yield kind, meta_name, node.get("spec") or {}
    elif kind == "CronJob":
        node = doc
        for key in ("spec", "jobTemplate", "spec", "template"):
            node = (node or {}).get(key) or {}
        yield kind, meta_name, node.get("spec") or {}
    elif kind == "List":
        for item in doc.get("items") or []:
            if isinstance(item, dict):
                yield from pod_specs(item)


def image_findings(image: str):
    out = []
    if "@sha256:" in image:
        return out  # digest-pinned: strongest form
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        out.append("IMG_UNTAGGED")  # implicit :latest
    elif last.rsplit(":", 1)[-1] == "latest":
        out.append("IMG_LATEST")
    out.append("IMG_NO_DIGEST")
    return out


def container_findings(c, pod_sc, kind):
    """c: container dict; pod_sc: pod-level securityContext."""
    out = []
    sc = c.get("securityContext") or {}
    if sc.get("privileged") is True:
        out.append("SEC_PRIVILEGED")
    if sc.get("allowPrivilegeEscalation") is not False:
        out.append("SEC_APE_NOT_DISABLED")
    run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
    run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
    if run_as_user == 0:
        out.append("SEC_RUN_AS_ROOT_EXPLICIT")
    elif run_as_non_root is not True:
        out.append("SEC_ROOT_NOT_PREVENTED")
    caps_add = ((sc.get("capabilities") or {}).get("add")) or []
    if any(x in caps_add for x in ("SYS_ADMIN", "ALL", "NET_ADMIN")):
        out.append("SEC_DANGEROUS_CAPABILITY")
    elif caps_add:
        out.append("SEC_CAPABILITY_ADDED")
    seccomp = sc.get("seccompProfile", pod_sc.get("seccompProfile")) or {}
    if not seccomp.get("type"):
        out.append("SEC_NO_SECCOMP")
    res = c.get("resources") or {}
    limits = res.get("limits") or {}
    requests = res.get("requests") or {}
    if "cpu" not in limits:
        out.append("RES_NO_CPU_LIMIT")
    if "memory" not in limits:
        out.append("RES_NO_MEM_LIMIT")
    if not requests:
        out.append("RES_NO_REQUESTS")
    out += image_findings(str(c.get("image", "")))
    if kind in LONG_RUNNING:
        if not c.get("livenessProbe"):
            out.append("REL_NO_LIVENESS_PROBE")
        if not c.get("readinessProbe"):
            out.append("REL_NO_READINESS_PROBE")
    for env in c.get("env") or []:
        if isinstance(env, dict) and env.get("value") and SECRET_ENV_RE.search(str(env.get("name", ""))):
            out.append("SECRET_LITERAL_ENV")
            break
    return out


def pod_findings(spec):
    out = []
    if spec.get("hostNetwork") is True:
        out.append("HOST_NETWORK")
    if spec.get("hostPID") is True:
        out.append("HOST_PID")
    if spec.get("hostIPC") is True:
        out.append("HOST_IPC")
    if spec.get("automountServiceAccountToken") is not False:
        out.append("SA_TOKEN_AUTOMOUNTED")
    return out


def analyze():
    findings = []
    stats = {}
    for arm in ARMS:
        arm_dir = ROOT / "corpus" / arm
        s = Counter()
        rule_counts = Counter()
        rule_workloads = defaultdict(set)
        files = sorted(arm_dir.glob("*.yaml")) + sorted(arm_dir.glob("*.yml"))
        for f in files:
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
                name = (doc.get("metadata") or {}).get("name", "?")
                if api in DEPRECATED_APIS:
                    findings.append({"arm": arm, "source": src, "kind": kind,
                                     "name": name, "container": None,
                                     "rule": "DEPRECATED_API"})
                    rule_counts["DEPRECATED_API"] += 1
                    s["docs_deprecated_api"] += 1
                if kind == "Secret":
                    findings.append({"arm": arm, "source": src, "kind": kind,
                                     "name": name, "container": None,
                                     "rule": "SECRET_COMMITTED"})
                    rule_counts["SECRET_COMMITTED"] += 1
                    s["secret_objects"] += 1
                if kind in ("Role", "ClusterRole"):
                    for rule in as_list(doc.get("rules")):
                        if not isinstance(rule, dict):
                            continue
                        if "*" in (rule.get("verbs") or []):
                            findings.append({"arm": arm, "source": src, "kind": kind,
                                             "name": name, "container": None,
                                             "rule": "RBAC_WILDCARD_VERBS"})
                            rule_counts["RBAC_WILDCARD_VERBS"] += 1
                        if "*" in (rule.get("resources") or []):
                            findings.append({"arm": arm, "source": src, "kind": kind,
                                             "name": name, "container": None,
                                             "rule": "RBAC_WILDCARD_RESOURCES"})
                            rule_counts["RBAC_WILDCARD_RESOURCES"] += 1
                if kind in ("RoleBinding", "ClusterRoleBinding"):
                    if ((doc.get("roleRef") or {}).get("name")) == "cluster-admin":
                        findings.append({"arm": arm, "source": src, "kind": kind,
                                         "name": name, "container": None,
                                         "rule": "RBAC_CLUSTER_ADMIN_BINDING"})
                        rule_counts["RBAC_CLUSTER_ADMIN_BINDING"] += 1
                for wkind, wname, spec in pod_specs(doc):
                    s["workloads"] += 1
                    pod_sc = spec.get("securityContext") or {}
                    wl_key = f"{src}:{wkind}/{wname}"
                    for rule in pod_findings(spec):
                        findings.append({"arm": arm, "source": src, "kind": wkind,
                                         "name": wname, "container": None, "rule": rule})
                        rule_counts[rule] += 1
                        rule_workloads[rule].add(wl_key)
                    containers = as_list(spec.get("containers")) + as_list(spec.get("initContainers"))
                    for c in containers:
                        if not isinstance(c, dict):
                            continue
                        s["containers"] += 1
                        for rule in container_findings(c, pod_sc, wkind):
                            findings.append({"arm": arm, "source": src, "kind": wkind,
                                             "name": wname,
                                             "container": c.get("name", "?"),
                                             "rule": rule})
                            rule_counts[rule] += 1
                            rule_workloads[rule].add(wl_key)
        denom_c = max(s["containers"], 1)
        denom_w = max(s["workloads"], 1)
        stats[arm] = {
            **dict(s),
            "rules": {
                r: {"findings": rule_counts[r],
                    "pct_containers": round(100 * rule_counts[r] / denom_c, 1),
                    "workloads_affected": len(rule_workloads[r]),
                    "pct_workloads": round(100 * len(rule_workloads[r]) / denom_w, 1)}
                for r in sorted(rule_counts)
            },
        }
        print(f"[{arm}] files={s['files']} docs={s['docs']} workloads={s['workloads']} "
              f"containers={s['containers']} findings={sum(rule_counts.values())}")
    (ROOT / "results" / "findings.jsonl").write_text(
        "\n".join(json.dumps(x) for x in findings) + "\n")
    (ROOT / "results" / "stats.json").write_text(json.dumps(stats, indent=2))
    print(f"\nTotal findings: {len(findings)} -> results/stats.json")


if __name__ == "__main__":
    analyze()
