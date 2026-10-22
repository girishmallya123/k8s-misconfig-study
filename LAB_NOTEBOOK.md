# Lab notebook

## 2026-10-21 — Project start
- Project conceived as an independent (non-affiliated) empirical study of how Kubernetes workloads are actually configured in the open — whether the manifests people ship match the hardening guidance the ecosystem publishes. Research questions and full plan written (see study plan).
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

## 2026-10-22 — Methods audit: protocol harmonization + reliability fix

- An external review flagged, and I verified against the repo: (1) two conflicting labeling protocols existed — root labeling-protocol.md (v1, exploitability standard) vs results/labeling_protocol.md (v2, definitional; pre-labels follow v2). (2) The 44/44 blind-duplicate agreement is intra-rater consistency, not inter-rater reliability; the v1 design called for a second labeler on a 30-row overlap for Cohen's kappa.
- Fix kit built (scripts/build_fix_kit.py): results/labeling_protocol_v3.md is now the single governing protocol (v2 core + v1 amendments: IMG_NO_DIGEST two-tier, RES/REL production-scoping, APE/ROOT escalation-path test, DEPRECATED_API as rot tier; SECRET/CAPABILITY/infra refinements carried). v1 and v2 files banner-marked superseded, retained for provenance.
- Divergence list (results/divergence_list.csv): 92 of 457 rows are standard-sensitive — A: 14 IMG_NO_DIGEST (re-tier as TP-hardening), B: 42 RES/REL TPs from example/fixture sources (FP under v3), C: 29 APE/ROOT TPs needing escalation-path verification (none auto-flip on packet evidence), D: 7 evidence-absent unsure rows (kustomize-injected images K8S-113/207/236/371 + unlocatable K8S-189; excluded from precision denominators, disclosed).
- Blinded kappa subset built (results/kappa_subset/): 30 unique-content rows across all 25 rules + packets + instructions; scripts/score_kappa.py computes author-vs-AI Cohen's kappa (smoke-tested). NEXT: Girish labels the blind subset cold (~30-60 min), then the verification pass (divergence rows first).

## 2026-10-22 (evening) — Second external review: RQ3 headlines corrected, engine v3

- A second external review was verified claim-by-claim against the raw tool outputs and engine code. Two RQ3 headlines were WRONG and are corrected in README + matrix: (1) the "CPU limits ~5x swing (76 vs 416)" — kubeaudit's LimitsNotSet (421, no limits at all) + LimitsCPUNotSet (76, limits block without CPU) = 497 vs engine 502 (~1% agreement; memory 474 vs 479); the real spread is 343-497 (~1.4x, counting units). The matrix's data rows were right; the narrative cherry-picked 76. (2) "Wildcard RBAC flagged by none" — the matrix itself lists Checkov CKV_K8S_49 at 29 findings; kube-linter ships wildcard checks off by default, so the legend now reads "no default-enabled check". The Secrets claim is reframed: no tool inspects Secret CONTENTS for credential material (~88% of sampled Secrets are empty/placeholder; the gap is the credential-bearing minority).
- Engine v3 (analyze.py + analyze_tagged.py): SA-token rule joins the ServiceAccount object's own automount flag (same file); init containers excluded from probe rules; seccompProfile.type=Unconfined counts as no profile; containers with no image field are not scored for IMG rules (counted as containers_no_image). Re-ran both arms on the identical corpus: findings 28,109 -> 27,460 (stats_v3.json / findings_v3.jsonl / stats_tagged_v3.json). Biggest deltas: Helm probe findings -30% (303->211 liveness) — a third of v2 probe findings were on init containers; SA barely moves (Helm 88.8%->85.1% of workloads, GitHub 96.4%->96.2%) so the v2 upper bound was tight; seccomp Helm 363->370.
- Non-independence addressed in results/cluster_prevalence.md: 52.9% of GitHub findings repeat a seen (kind,name,container,rule) key, but cluster-level presence is ecosystem-wide (SA automount in 94% of repos / 90% of charts; privileged only 22% / 8%).
- Reproducibility: GitHub arm was collected with git clone --depth 1 and no SHAs logged; the local clones were untouched since collection, so HEAD SHAs for all 60 repos are now recorded in results/github_commit_shas.json.
- README scope fixes: "16,243 manifests" -> YAML documents (2,811 workloads); whole-corpus counts (415/341) removed from the Helm-arm RQ3 claims.
- NEXT: Girish's blind kappa subset + verification pass (protocol v3, divergence rows first); then taxonomy v2 (adds readOnlyRootFilesystem) and the paper draft.
