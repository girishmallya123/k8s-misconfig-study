# Misconfigured by Default — a Kubernetes misconfiguration study

**How Kubernetes manifests are actually configured in the wild — and whether the tools
that audit them agree.**

An empirical measurement study of Kubernetes configuration practices across 16,243
YAML documents (2,811 workloads) drawn from public sources, plus a comparative audit
of the four most widely used manifest-auditing tools on identical input.

## Research questions

- **RQ1 — Prevalence.** How common is each class of misconfiguration in real-world manifests?
- **RQ2 — Taxonomy.** Can observed misconfigurations be organized into a stable taxonomy
  (25 rules in v1) spanning security context, resources, images, reliability, RBAC, and secrets?
- **RQ3 — Auditing the auditors.** On identical input, how much of the observed taxonomy do
  kube-linter, kubeaudit, Polaris, and Checkov actually cover — and do their counts agree?
- **RQ4 — Curation effect.** Do rendered Helm charts (curated, templated) differ from raw
  manifests committed to Git repositories?

## Headline findings (October 2026 corpus)

- Service-account tokens are automounted in **85–96%** of workloads; CPU limits are missing
  in **79–86%**; images are not digest-pinned in **84–98%** — across both corpus arms
  (workload-level rates, engine v3).
- Curated Helm charts are better hardened than raw GitHub manifests, but by **~1.3–1.7×**,
  not the 2–3× a top-60-charts sample suggests (best-chart bias, measured and corrected).
- Restricting the analysis to production manifests only (excluding examples and test
  fixtures) barely moves the headline numbers: SA tokens are still automounted in
  **88.6%** of production workloads (96.2% corpus-wide) and CPU limits are missing in
  **75.3%** (79.0%). The risky defaults are in shipped code, not test files.
- **RQ3** (Helm arm, identical input for all four tools): the widest tool (Checkov) covers
  only ~16 of 25 observed practices. Digest pinning is checked by 1 of 4 tools. Wildcard
  RBAC has no *default-enabled* check that catches it broadly — Checkov partially flags
  it (29 of 155 findings) and kube-linter ships wildcard checks that are off by default.
  No tool inspects committed Secret objects' *contents*: none distinguishes a Secret
  holding real credential material from an empty or placeholder one (validation sampling
  found ~88% of committed Secrets are empty/placeholder — the exposure is the
  credential-bearing minority). Counts for the same practice diverge by counting
  semantics: "CPU limits missing" yields 343 / 411 / 416 / 497 findings across the four
  tools against 502 container-level cases — a ~1.4× spread from pod- vs container-level
  units and merged request/limit checks. The tools agree almost exactly only on explicit
  dangers (e.g. privileged containers: 26–27 from every tool), and diverge on
  default-insecure configurations, where most risk lives.

Full numbers: `results/` (stats JSONs, sensitivity tables, tool coverage matrix).

## Corpus

| Arm | Sources | Documents | Workloads |
|---|---|---|---|
| Helm | 151 charts from Artifact Hub (rendered with default values) | 2,616 | 402 |
| GitHub | 60 public repositories (seed projects + search-discovered) | 13,627 | 2,409 |

The corpus itself is **not redistributed here** (third-party manifests carry mixed
licenses). The collection scripts and the per-source collect logs in `results/` are the
corpus manifest: running the collectors rebuilds it from public sources. The GitHub
snapshots analyzed are pinned by commit in `results/github_commit_shas.json`.

## Repository layout

- `scripts/` — collectors (`collect_helm*.py`, `collect_github*.py`), the rule engine
  (`analyze.py`), source tagging/sensitivity (`analyze_tagged.py`), the RQ3 tool runner
  (`run_tools.sh`), and the validation-sample builder (`build_labeling_sample.py`).
- `results/` — aggregate statistics (pilot, v2, per-source-tag), derived findings,
  the tool coverage matrix, and the validation labeling sample + protocol.
- `LAB_NOTEBOOK.md` — dated research log: decisions, dead ends, and corrections.

## Reproducing

```bash
python3 scripts/collect_helm2.py     # renders top Artifact Hub charts (needs helm 3)
python3 scripts/collect_github2.py   # clones/mines public manifest repos
python3 scripts/analyze.py           # rule engine -> results/stats.json, findings.jsonl
python3 scripts/analyze_tagged.py    # per-source-type sensitivity analysis
bash    scripts/run_tools.sh         # RQ3: kube-linter / kubeaudit / Polaris / Checkov
```

## Validation

Prevalence numbers are only as good as the rules' precision. `results/labeling_sample_v2.csv`
is a 457-finding stratified sample (all high-severity findings included, ~10% hidden duplicates
for agreement scoring) governed by the labeling protocol in `results/labeling_protocol_v3.md`
(a blinded 30-row subset for inter-rater reliability lives in `results/kappa_subset/`).
Per-rule precision from that pass will be published with the paper.

## Status

Independent research project, October 2026. Public data only; personal resources only;
no employer code, data, or affiliation. Analysis phases complete; manual validation in
progress. A paper is in preparation — primary venue: *Empirical Software Engineering*
(Springer), journal route, no conference presentation.

## License

Apache-2.0 (see `LICENSE`). The corpus manifests remain under their original licenses.
