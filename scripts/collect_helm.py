#!/usr/bin/env python3
"""Collect the Helm arm of the corpus: most-starred charts from Artifact Hub,
rendered with default values via `helm template`.

Output: corpus/helm/<chart>.yaml  +  results/helm_render_log.json
"""
import io
import json
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELM = ROOT / "bin" / "helm"
TGZ_DIR = ROOT / "corpus_src" / "helm_tgz"
CHART_DIR = ROOT / "corpus_src" / "charts"
OUT_DIR = ROOT / "corpus" / "helm"
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 60

for d in (TGZ_DIR, CHART_DIR, OUT_DIR):
    d.mkdir(parents=True, exist_ok=True)


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "k8s-misconfig-study/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_bytes(url):
    req = urllib.request.Request(url, headers={"User-Agent": "k8s-misconfig-study/0.1"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def main():
    search = fetch_json(
        f"https://artifacthub.io/api/v1/packages/search?kind=0&limit={LIMIT}&offset=0"
    )
    packages = search.get("packages", [])
    print(f"Artifact Hub returned {len(packages)} charts")
    log = []
    for pkg in packages:
        name = pkg.get("normalized_name") or pkg.get("name")
        repo = (pkg.get("repository") or {}).get("name", "")
        version = pkg.get("version", "")
        content_url = pkg.get("content_url")
        entry = {"chart": name, "repo": repo, "version": version}
        if not content_url:
            try:
                detail = fetch_json(
                    f"https://artifacthub.io/api/v1/packages/helm/{repo}/{name}"
                )
                content_url = detail.get("content_url")
            except Exception as e:  # noqa: BLE001
                entry["status"] = f"no content_url: {e}"
                log.append(entry)
                continue
        if not content_url:
            entry["status"] = "no content_url"
            log.append(entry)
            continue
        try:
            blob = fetch_bytes(content_url)
            tgz_path = TGZ_DIR / f"{name}-{version}.tgz"
            tgz_path.write_bytes(blob)
            chart_path = CHART_DIR / f"{name}-{version}"
            if chart_path.exists():
                subprocess.run(["rm", "-rf", str(chart_path)])
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
                tf.extractall(CHART_DIR / "_tmp_extract", filter="data")
            extracted = CHART_DIR / "_tmp_extract"
            roots = [p for p in extracted.iterdir() if p.is_dir()]
            if not roots:
                entry["status"] = "empty tarball"
                log.append(entry)
                continue
            roots[0].rename(chart_path)
            subprocess.run(["rm", "-rf", str(extracted)])
        except Exception as e:  # noqa: BLE001
            entry["status"] = f"download/extract failed: {e}"
            log.append(entry)
            continue
        # Render with default values
        try:
            proc = subprocess.run(
                [str(HELM), "template", "pilot", str(chart_path),
                 "--namespace", "default"],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0:
                entry["status"] = "render failed"
                entry["stderr"] = proc.stderr.strip().splitlines()[-1][:300] if proc.stderr.strip() else ""
                log.append(entry)
                continue
            out = OUT_DIR / f"{name}.yaml"
            out.write_text(proc.stdout)
            n_docs = proc.stdout.count("\n---")
            entry["status"] = "ok"
            entry["docs_approx"] = n_docs + 1
            log.append(entry)
            print(f"ok   {name} ({repo}) ~{n_docs + 1} docs")
        except Exception as e:  # noqa: BLE001
            entry["status"] = f"render exception: {e}"
            log.append(entry)
    ok = sum(1 for e in log if e["status"] == "ok")
    total_docs = sum(e.get("docs_approx", 0) for e in log if e["status"] == "ok")
    print(f"\nRendered {ok}/{len(log)} charts, ~{total_docs} documents total")
    (ROOT / "results" / "helm_render_log.json").write_text(json.dumps(log, indent=2))


if __name__ == "__main__":
    main()
