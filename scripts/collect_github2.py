#!/usr/bin/env python3
"""GitHub arm scale-up (v2). Adds manifest-heavy seed repos plus repos
discovered via the GitHub repository search API (unauthenticated; results
filtered by size). Same keep-filter as v1: file parses as YAML and contains
at least one apiVersion+kind document.

Output: corpus/github/<repo>__<path>.yaml + results/github_collect_log_v2.json
"""
import json
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "corpus_src" / "repos"
OUT = ROOT / "corpus" / "github"
SRC.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)

EXTRA_SEEDS = [
    "kubernetes-sigs/kustomize",
    "argoproj/argo-cd",
    "argoproj/argo-rollouts",
    "fluxcd/flux2",
    "knative/docs",
    "tektoncd/pipeline",
    "crossplane/crossplane",
    "grafana/loki",
    "elastic/cloud-on-k8s",
    "zalando/postgres-operator",
    "strimzi/strimzi-kafka-operator",
    "kubernetes-sigs/metrics-server",
]

SEARCH_QUERIES = [
    "kubernetes manifests in:name,description",
    "gitops kubernetes in:description",
    "kubernetes examples in:description",
    "kubernetes operator manifests in:description",
]
MAX_DISCOVERED = 40
MIN_SIZE_KB, MAX_SIZE_KB = 200, 400_000


def fetch_json(url):
    req = urllib.request.Request(
        url, headers={"User-Agent": "k8s-misconfig-study/0.2",
                      "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def has_k8s_doc(path: Path) -> int:
    try:
        text = path.read_text(errors="ignore")
        if "apiVersion" not in text or "kind:" not in text:
            return 0
        n = 0
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict) and doc.get("apiVersion") and doc.get("kind"):
                n += 1
        return n
    except Exception:  # noqa: BLE001
        return 0


def discover():
    found = {}
    for q in SEARCH_QUERIES:
        try:
            url = ("https://api.github.com/search/repositories?q="
                   + urllib.parse.quote(q)
                   + "&sort=stars&order=desc&per_page=50")
            data = fetch_json(url)
            for item in data.get("items", []):
                size = item.get("size", 0)
                if MIN_SIZE_KB <= size <= MAX_SIZE_KB:
                    found[item["full_name"]] = size
            print(f"query '{q}': {len(data.get('items', []))} results")
        except Exception as e:  # noqa: BLE001
            print(f"query '{q}' failed: {e}")
        time.sleep(8)  # unauthenticated search rate limit: 10/min
    return list(found.keys())[:MAX_DISCOVERED]


def collect(repo, log):
    name = repo.replace("/", "_")
    dest = SRC / name
    entry = {"repo": repo}
    if dest.exists() and any(OUT.glob(name + "__*.yaml")):
        entry["status"] = "already in corpus"
        log.append(entry)
        return
    if not dest.exists():
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet",
             f"https://github.com/{repo}.git", str(dest)],
            capture_output=True, text=True, timeout=900)
        if proc.returncode != 0:
            entry["status"] = "clone failed"
            entry["stderr"] = proc.stderr.strip()[-250:]
            log.append(entry)
            print(f"FAIL clone {repo}")
            return
    files = list(dest.rglob("*.yaml")) + list(dest.rglob("*.yml"))
    kept, docs = 0, 0
    for f in files:
        if ".git" in f.parts:
            continue
        n = has_k8s_doc(f)
        if n:
            rel = f.relative_to(dest)
            flat = name + "__" + "__".join(rel.parts)
            (OUT / flat).write_bytes(f.read_bytes())
            kept += 1
            docs += n
    entry.update({"status": "ok", "files_kept": kept, "docs_kept": docs})
    log.append(entry)
    print(f"ok   {repo}: kept {kept} files / {docs} docs")


def main():
    log = []
    existing = {p.name for p in SRC.iterdir() if p.is_dir()} if SRC.exists() else set()
    seeds = [r for r in EXTRA_SEEDS if r.replace("/", "_") not in existing]
    print(f"{len(seeds)} new seed repos")
    for repo in seeds:
        collect(repo, log)
    discovered = [r for r in discover()
                  if r.replace("/", "_") not in existing and r not in EXTRA_SEEDS]
    print(f"{len(discovered)} discovered repos to collect")
    for repo in discovered:
        collect(repo, log)
    (ROOT / "results" / "github_collect_log_v2.json").write_text(json.dumps(log, indent=2))
    total = sum(e.get("docs_kept", 0) for e in log if e["status"] == "ok")
    print(f"\nGitHub v2 added: {total} documents")


if __name__ == "__main__":
    main()
