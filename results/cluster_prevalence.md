# Cluster-level prevalence and deduplication (engine v3, 2026-10-22)

Findings within a repository or chart are not independent observations:
install bundles repeat the same workloads across files, and a few large
repos dominate the GitHub arm (kubescape/regolibrary alone contributes
36.7% of v2 GitHub findings; it is fixture-tagged). This note reports the
two robustness views a reviewer should ask for. All numbers are from
`results/findings_v3.jsonl` (engine v3: SA-object join, init containers
excluded from probe rules, seccomp `Unconfined` treated as no profile,
missing image fields not scored).

## Deduplication

Collapsing GitHub-arm findings to unique (kind, name, container, rule)
keys: 23,280 findings → 10,973 unique keys; **52.9% of findings repeat an
already-seen key** (argo-cd install variants, regula/regolibrary test
inputs, and copied example workloads account for most repeats). Any
per-finding rate must therefore be read alongside the cluster view below,
and the paper's prevalence claims are stated per workload and per
cluster, not per finding.

## Cluster-level presence

Share of clusters (repos / chart files) in which a rule fires at least
once — the "is this practice ecosystem-wide or driven by a few sources?"
test:

| Rule | GitHub repos (n=54 with findings) | Helm charts (n=144 with findings) |
|---|---|---|
| SA_TOKEN_AUTOMOUNTED | 94% | 90% |
| SEC_NO_SECCOMP | 94% | 72% |
| IMG_NO_DIGEST | 91% | 97% |
| RES_NO_CPU_LIMIT | 83% | 92% |
| SEC_PRIVILEGED | 22% | 8% |

The default-insecure practices (SA automount, no seccomp, unpinned
images, missing CPU limits) appear in the large majority of independent
sources in both arms — they are not artifacts of the biggest repos. The
explicit-danger practice (privileged containers) is comparatively rare
at cluster level too, consistent with the per-workload rates.

## Engine v2 → v3 corrections behind these numbers

- SA-token rule now joins the ServiceAccount object's own
  `automountServiceAccountToken` (same-file): Helm 357 → 342 findings
  (88.8% → 85.1% of workloads), GitHub 2,339 → 2,334 (96.4% → 96.2%).
  The v2 figures were upper bounds; the join moves them only slightly.
- Init containers excluded from probe rules: Helm liveness findings
  303 → 211 (−30%), readiness 296 → 204; GitHub 1,821 → 1,682 and
  1,835 → 1,696. A substantial share of v2 probe findings were spurious.
- seccomp `type: Unconfined` now counts as no profile: Helm 363 → 370.
- Containers with no image field (87 in the GitHub arm, kustomize-style
  bases) are no longer scored IMG_UNTAGGED / IMG_NO_DIGEST:
  untagged 662 → 575, no-digest 2,456 → 2,369; excluded-and-disclosed
  per protocol v3.
- Total findings 28,109 → 27,460 on an identical corpus (16,243
  documents, 2,811 workloads).
