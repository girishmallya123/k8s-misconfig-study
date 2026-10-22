#!/usr/bin/env python3
"""Helm arm scale-up (v2). Extends collect_helm.py:
- paginates Artifact Hub search to the top ~200 charts (deduped by name)
- skips charts already rendered in corpus/helm/
- supports OCI-distributed charts via `helm pull`
- on render failure, tries `helm dependency update` (adding dep repos first)
  and retries once

Output: corpus/helm/<chart>.yaml + results/helm_render_log_v2.json
"""
import hashlib
import io
import json
import subprocess
import tarfile
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
HELM = ROOT / "bin" / "helm"
TGZ_DIR = ROOT / "corpus_src" / "helm_tgz"
CHART_DIR = ROOT / "corpus_src" / "charts"
OUT_DIR = ROOT / "corpus" / "helm"
for d in (TGZ_DIR, CHART_DIR, OUT_DIR):
    d.mkdir(parents=True, exist_ok=True)


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "k8s-misconfig-study/0.2"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_bytes(url):
    req = urllib.request.Request(url, headers={"User-Agent": "k8s-misconfig-study/0.2"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def run(cmd, timeout=180):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def get_tgz(name, version, content_url):
    dest = TGZ_DIR / f"{name}-{version}.tgz"
    if dest.exists():
        return dest
    if content_url.startswith("oci://"):
        proc = run([str(HELM), "pull", content_url, "--version", version,
                    "--destination", str(TGZ_DIR)], timeout=300)
        if proc.returncode != 0:
            raise RuntimeError(f"helm pull failed: {proc.stderr.strip()[-200:]}")
        produced = sorted(TGZ_DIR.glob(f"*.tgz"), key=lambda p: p.stat().st_mtime)
        if not produced:
            raise RuntimeError("helm pull produced no tgz")
        return produced[-1]
    dest.write_bytes(fetch_bytes(content_url))
    return dest


def extract(tgz_path, name, version):
    chart_path = CHART_DIR / f"{name}-{version}"
    if chart_path.exists():
        return chart_path
    tmp = CHART_DIR / f"_tmp_{name}"
    if tmp.exists():
        subprocess.run(["rm", "-rf", str(tmp)])
    with tarfile.open(tgz_path, mode="r:gz") as tf:
        tf.extractall(tmp, filter="data")
    roots = [p for p in tmp.iterdir() if p.is_dir()]
    if not roots:
        raise RuntimeError("empty tarball")
    roots[0].rename(chart_path)
    subprocess.run(["rm", "-rf", str(tmp)])
    return chart_path


def add_dep_repos(chart_path):
    try:
        cy = yaml.safe_load((chart_path / "Chart.yaml").read_text())
    except Exception:  # noqa: BLE001
        return
    for dep in (cy or {}).get("dependencies") or []:
        url = str(dep.get("repository", ""))
        if url.startswith("http"):
            rname = "r" + hashlib.md5(url.encode()).hexdigest()[:10]
            run([str(HELM), "repo", "add", rname, url], timeout=120)


def render(chart_path):
    return run([str(HELM), "template", "pilot", str(chart_path),
                "--namespace", "default"], timeout=180)


def main():
    packages, seen = [], set()
    for offset in (0, 60, 120, 180):  # API caps limit at 60
        try:
            page = fetch_json(
                f"https://artifacthub.io/api/v1/packages/search?kind=0&limit=60&offset={offset}"
            )
        except Exception as e:  # noqa: BLE001
            print(f"search page offset={offset} failed: {e}")
            break
        for pkg in page.get("packages", []):
            nm = pkg.get("normalized_name") or pkg.get("name")
            if nm and nm not in seen:
                seen.add(nm)
                packages.append(pkg)
    print(f"{len(packages)} unique charts to consider")
    log = []
    dep_retries = 0
    MAX_DEP_RETRIES = 8  # dep updates are slow; cap total attempts
    for pkg in packages:
        name = pkg.get("normalized_name") or pkg.get("name")
        repo = (pkg.get("repository") or {}).get("name", "")
        version = pkg.get("version", "")
        entry = {"chart": name, "repo": repo, "version": version}
        if (OUT_DIR / f"{name}.yaml").exists():
            entry["status"] = "already in corpus"
            log.append(entry)
            continue
        content_url = pkg.get("content_url")
        if not content_url:
            try:
                detail = fetch_json(
                    f"https://artifacthub.io/api/v1/packages/helm/{repo}/{name}")
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
            tgz = get_tgz(name, version, content_url)
            chart_path = extract(tgz, name, version)
        except Exception as e:  # noqa: BLE001
            entry["status"] = f"download/extract failed: {e}"[:250]
            log.append(entry)
            continue
        try:
            proc = render(chart_path)
        except Exception as e:  # noqa: BLE001
            entry["status"] = f"render exception: {e}"[:250]
            log.append(entry)
            continue
        if proc.returncode != 0:
            entry["dep_retry"] = True
            if dep_retries >= MAX_DEP_RETRIES:
                entry["status"] = "render failed (dep retry budget exhausted)"
                log.append(entry)
                continue
            dep_retries += 1
            try:
                add_dep_repos(chart_path)
                run([str(HELM), "dependency", "update", str(chart_path)], timeout=90)
                proc = render(chart_path)
            except Exception as e:  # noqa: BLE001
                entry["status"] = f"dep retry failed: {e}"[:250]
                log.append(entry)
                continue
        if proc.returncode != 0:
            entry["status"] = "render failed"
            entry["stderr"] = (proc.stderr.strip().splitlines() or [""])[-1][:250]
            log.append(entry)
            continue
        (OUT_DIR / f"{name}.yaml").write_text(proc.stdout)
        entry["status"] = "ok"
        entry["docs_approx"] = proc.stdout.count("\n---") + 1
        log.append(entry)
        print(f"ok   {name} ({repo}) ~{entry['docs_approx']} docs")
    ok = sum(1 for e in log if e["status"] == "ok")
    skipped = sum(1 for e in log if e["status"] == "already in corpus")
    docs = sum(e.get("docs_approx", 0) for e in log if e["status"] == "ok")
    print(f"\nNew renders ok: {ok} (skipped {skipped} already in corpus), ~{docs} new docs")
    (ROOT / "results" / "helm_render_log_v2.json").write_text(json.dumps(log, indent=2))


if __name__ == "__main__":
    main()
