# Lab notebook

## 2026-10-21 — Project start
- Project conceived as an independent (non-affiliated) empirical study for the NIW evidence portfolio. Research questions and full plan written (see goal workspace plan doc).
- Scaffolded repo; installed Helm v3.16.3 locally for chart rendering.
- Pilot goal: collect a first corpus (top Helm charts rendered with default values + raw manifests from public GitHub repos), run the taxonomy rule engine end-to-end, and sanity-check prevalence numbers before scaling.
- Taxonomy v1 seeded from the CIS Kubernetes Benchmark and NSA/CISA Kubernetes Hardening Guidance categories: security context, resource hygiene, image hygiene, RBAC, host namespaces, secrets handling, probes, deprecated APIs.
- Design decision: distinguish the two corpus arms (rendered Helm vs raw GitHub manifests) in all stats — the Helm-vs-raw split is RQ4 and a likely headline result.
- Design decision: RQ3 ("auditing the auditors") deferred to phase 2 — pilot validates the mining + rule engine first.

## 2026-10-21 — Pilot complete (same day)
- Helm arm: 41/60 top Artifact Hub charts rendered (~994 docs). Failures: 12 OCI-distributed charts (need `helm pull` support), 7 needing deps/values.
- GitHub arm: 9 seed repos, 1,721 files / 2,389 docs kept. argo-workflows dominates (1,185 docs) — stratification needed at scale-up.
- Analyzer ran clean: 3,383 docs, 460 workloads, 534 containers, 3,958 findings across 24 rules.
- Headline: curated charts are 2–3× better hardened than raw repo manifests (seccomp gaps 41% vs 89%; root-not-prevented 30% vs 65%; untagged images 0.8% vs 32.5%), but SA-token automounting (~90%+) and missing resource limits (~70–80%) are near-universal in both arms.
- Verdict: feasible; RQ4 contrast is real. Next: scale-up fixes, labeling sample, RQ3 tool-coverage matrix.

## 2026-10-21 — Scale-up complete
- Fixes shipped: Artifact Hub pagination (API caps limit at 60), OCI chart pulls, dependency-update retries with a budget cap (gitlab's dep update hangs >90s — budget exhaust is a feature, not a bug).
- Corpus v2: Helm 151 charts / 2,616 docs; GitHub 60 repos / 13,627 docs; total 16,243 docs, 2,811 workloads, 28,109 findings. Stats: results/stats_v2.json (pilot preserved as stats_pilot.json).
- Effect-size correction: Helm-vs-GitHub security gap narrowed from the pilot's 2–3× to ~1.3–1.7× once less-polished charts entered the sample. Pilot's top-60 was a best-case slice. Recorded honestly in the memo.
- New taxonomy insight: privileged containers concentrate in infrastructure DaemonSets (by design) — taxonomy v2 needs an infra-agent vs application workload split.
- Corpus concentration risk: top-3 GitHub sources ≈49% of v2 docs; kubescape/regolibrary contains intentional good/bad test fixtures. Source tagging (production / example / fixture) is now a prerequisite for prevalence claims.
- Analyzer hardened: real-world YAML includes dict-shaped `containers` fields and other malformed specs; rule engine now coerces/skips safely.

## 2026-10-21 (evening) — Sensitivity, RQ3, labeling sample
- Source tagging shipped (scripts/analyze_tagged.py): production-only cut (1,780 files / 438 workloads) keeps the headline intact (SA tokens 89.7%, no CPU limit 75.3%) — findings are not fixture-driven. One correction en route: kubernetes/examples initially tagged production by path heuristics; repo-identity override added.
- RQ3 complete on the Helm arm (identical input, default settings): kube-linter 0.8.3 (1,925 reports), kubeaudit 0.22.2 (3,379 results; prints its own deprecation notice), Polaris 10.2.5, Checkov 3.3.30 (6,178 failed checks). Matrix: results/tool_coverage_matrix.md. Headlines: best tool covers ~16/25 rules; digest pinning checked by 1 of 4 tools; committed Secrets and wildcard RBAC by none; CPU-limit counts spread 76–416 across tools vs 502 actual.
- Taxonomy v2 changes queued from RQ3: add read-only-rootfs rule (all four tools have it; we don't); keep infra-agent split.
- Labeling sample v2 built: 457 rows, seed 42, all SEC_PRIVILEGED + RBAC_CLUSTER_ADMIN_BINDING, stratified rest, ~10% hidden duplicates for kappa. Protocol: results/labeling_protocol.md. Awaiting Girish's labeling pass.
- Ops note: a runtime restart mid-run killed two background jobs; kube-linter output survived and validated, the rest were re-run cleanly. Verify-before-retry paid off.



## 2026-10-21 — Validation sample built (evening)
- Built stratified 302-finding hand-labeling sample from pilot findings (`labeling_sample_pilot_v1.csv`, seeded RNG for reproducibility).
- Design: ALL high-severity/rare findings (SEC_PRIVILEGED 11, RBAC_CLUSTER_ADMIN_BINDING 2, HOST_NETWORK 14, HOST_PID 7, HOST_IPC 2, SEC_DANGEROUS_CAPABILITY 7, SEC_RUN_AS_ROOT_EXPLICIT 4, RBAC_WILDCARD_{VERBS,RESOURCES} 29, SECRET_LITERAL_ENV 37, SECRET_COMMITTED sampled 40 arm-stratified) + all SEC_CAPABILITY_ADDED 30 + DEPRECATED_API 30 + IMG_{UNTAGGED,LATEST} 40 + 50-finding round-robin sample across the 10 common rules.
- Each row: sample_id, arm, rule, severity, kind, name, container, source_file, absolute corpus_path, blank label_TP_FP_unsure, blank reviewer_notes. Verified: all 302 corpus paths resolve.
- Labeling protocol to use: label each finding TP/FP/unsure against taxonomy v1; double-label a random 10% subset (S001..S030) with a second reviewer to report Cohen's kappa.

## 2026-10-21 — AI pre-labeling of the v2 validation sample (late evening)
- Girish approved AI pre-labeling with author verification (his labels remain ground truth).
- Built evidence packets for all 457 rows (extract_packets.py); judged each row with a written one-line justification → results/labeling_sample_v2_prelabelled.csv (prelabel + prelabel_reason + blank your_label/your_notes).
- Outcome: 328 TP / 122 FP / 7 unsure (draft precision ≈73%). Blind duplicate agreement 44/44 groups. Spot-checks (5 rows across rules) verified against raw YAML.
- Taxonomy-v2 signals: SECRET_COMMITTED must require credential material (12% as defined); SEC_CAPABILITY_ADDED must exclude least-privilege patterns (24%); host-namespace rules + SEC_PRIVILEGED need the infra-agent class; SECRET_LITERAL_ENV must exclude *_FILE/_NAME references and policy settings (40%).
- Extraction caveat found: duplicate-named ClusterRoles in Argo CD bundles (4 rows hand-verified).
- NEXT: Girish's verification pass on the pre-labeled CSV → final per-rule precision → taxonomy v2.
