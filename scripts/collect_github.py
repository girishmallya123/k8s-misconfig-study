#!/usr/bin/env python3
"""Collect the GitHub arm of the corpus: raw Kubernetes manifests from public
repositories (shallow clones). Files that parse as YAML and contain at least
one document with apiVersion+kind are copied into corpus/github/.

Output: corpus/github/<repo>__<flattened-path>.yaml + results/github_collect_log.json
"""
import json
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "corpus_src" / "repos"
OUT = ROOT / "corpus" / "github"
SRC.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)

REPOS = [
    "kubernetes/examples",
    "argoproj/argocd-example-apps",
    "GoogleCloudPlatform/microservices-demo",
    "GoogleCloudPlatform/bank-of-anthos",
    "prometheus-operator/kube-prometheus",
    "kubernetes/ingress-nginx",
    "argoproj/argo-workflows",
    "fluxcd/flux2-kustomize-helm-example",
    "helm/charts",
]


def has_k8s_doc(path: Path) -> int:
    """Return number of k8s docs in file, 0 if none/unparseable."""
    try:
        text = path.read_text(errors="ignore")
        if "apiVersion" not in text or "kind:" not in text:
            return 0
        n = 0
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict) and doc.get("apiVersion") and doc.get("kind"):
                n += 1
        return n
    except Exception:  # noqa: BLE001 - templated/invalid YAML is expected in chart repos
        return 0


def main():
    log = []
    for repo in REPOS:
        name = repo.replace("/", "_")
        dest = SRC / name
        entry = {"repo": repo}
        if not dest.exists():
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet",
                 f"https://github.com/{repo}.git", str(dest)],
                capture_output=True, text=True, timeout=900,
            )
            if proc.returncode != 0:
                entry["status"] = "clone failed"
                entry["stderr"] = proc.stderr.strip()[-300:]
                log.append(entry)
                print(f"FAIL clone {repo}")
                continue
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
        entry.update({"status": "ok", "yaml_files_seen": len(files),
                      "files_kept": kept, "docs_kept": docs})
        log.append(entry)
        print(f"ok   {repo}: kept {kept} files / {docs} docs of {len(files)} yaml files")
    (ROOT / "results" / "github_collect_log.json").write_text(json.dumps(log, indent=2))
    total = sum(e.get("docs_kept", 0) for e in log)
    print(f"\nGitHub arm total: {total} documents")


if __name__ == "__main__":
    main()
