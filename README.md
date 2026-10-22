# Misconfigured by Default — a Kubernetes misconfiguration study

An independent empirical research project: how common are Kubernetes misconfigurations in public manifests and Helm charts, what forms do they take, and how well do existing linters cover what actually occurs in the wild?

- **Paper plan:** `~/workspace/goals/build-my-profile-for-eb-2-niw-acceptance/files/k8s-misconfiguration-study-plan.md`
- **Lab notebook:** `LAB_NOTEBOOK.md` (dated entries; documents originality and timeline)
- **Corpus:** `corpus/helm/` (rendered Helm charts from Artifact Hub's most-starred) and `corpus/github/` (raw manifests from public GitHub repos)
- **Pipeline:** `scripts/collect_helm.py` → `scripts/collect_github.py` → `scripts/analyze.py`
- **Results:** `results/stats.json`, `results/findings.jsonl`

Guardrails: public data only; personal resources only; no employer code, data, or affiliation.
