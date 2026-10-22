# Labeling protocol — v3 (GOVERNING)

**Status:** This protocol governs the v2 validation sample
(`results/labeling_sample_v2.csv`, 457 rows) and the paper's reported
precision figures. It supersedes both earlier protocols, which are retained
for provenance:

- `labeling-protocol.md` (v1, pilot era) — exploitability standard.
- `results/labeling_protocol.md` (v2) — definitional standard; the AI
  pre-labels were produced under it (see its addendum).

**Why v3 exists.** An external methods review (2026-10-22) found that v1 and
v2 ask different questions — v1: *"a genuine, exploitable hardening gap in a
realistic deployment?"*; v2: *"does the manifest exhibit the property the
rule names, in context?"* — and that the pre-labels follow v2. v3 merges
them: the definitional core of v2, with v1's per-rule refinements adopted
as explicit amendments where they encode real distinctions (image-digest
tiers, context sources for resource/probe rules, escalation-path tests).
Rows where the two standards can disagree are enumerated in
`results/divergence_list.csv` (92 rows) and are re-adjudicated under v3
during the author's verification pass; all other rows are
standard-invariant.

## The labeling question (v3)

> **Does this manifest, in context, exhibit the misconfiguration the rule
> names — judged by the per-rule tests below?**

- **TP** — yes, per the rule's test.
- **FP** — no: benign by design (infrastructure role with genuine need),
  placeholder/reference content, a context the rule's test excludes, or a
  parser artifact. Record the reason using the v1 codes: `infra-need`,
  `placeholder`, `fixture`, `standard-practice`, `parser-artifact`,
  `not-exploitable`.
- **unsure** — cannot be decided from the manifest and its evidence packet
  alone. Unsure rows are handled by the evidence-absent rule below, never
  silently dropped.

## Amendments adopted from v1

1. **Image digests are two-tier.** `IMG_UNTAGGED` and `IMG_LATEST` are
   misconfigurations (TP). `IMG_NO_DIGEST` with an *explicit version tag*
   is recorded as **TP-hardening** — a hardening gap, not a
   misconfiguration — and reported as its own tier in the paper (prevalence
   of missing digest pinning is reported, but not folded into
   misconfiguration precision). Affects 14 pre-labeled rows (divergence
   class A).
2. **Resource/probe rules are production-scoped.** For `RES_*` and `REL_*`
   rules, findings in `example`- or `fixture`-tagged sources (and one-shot
   Jobs) are FP *for the purposes of this validation* — the corpus-level
   prevalence already reports production-only figures separately via
   source tagging, and the sample mirrors that decision. Affects 42 rows
   (class B).
3. **Escalation-path test for `SEC_APE_NOT_DISABLED` /
   `SEC_ROOT_NOT_PREVENTED`.** TP requires a real escalation path: the
   container runs as root (or doesn't prevent it in a way that binds),
   adds capabilities, or has a writable root filesystem with setuid risk.
   Non-root + no added caps = `not-exploitable` FP. Affects 29 rows flagged
   for verification against their packets (class C).
4. **`DEPRECATED_API` is manifest rot, not misconfiguration.** Labels stay
   TP (the apiVersion fact is not in dispute) but the rule is reported in
   its own tier, excluded from misconfiguration precision aggregates.

## Refinements carried from the v2 pre-labeling analysis

5. **`SECRET_COMMITTED` requires credential material.** Empty Secrets,
   operator-populated placeholders, documented placeholder values,
   template/reference values (`${...}`, `<...>`), and credential-free
   connection strings (URLs without a password) are FP. Non-empty literal
   passwords, tokens, and private keys are TP.
6. **`SEC_CAPABILITY_ADDED` excludes least-privilege patterns.** Adding
   only default-set capabilities, or `NET_BIND_SERVICE` alongside
   `drop: [ALL]`, is FP (functional, least-privilege). Genuinely dangerous
   additions are `SEC_DANGEROUS_CAPABILITY`'s scope.
7. **Infrastructure class for host/privileged rules.** `SEC_PRIVILEGED`,
   `HOST_NETWORK`, `HOST_PID`, `HOST_IPC` findings on node-level agents
   whose function requires the access (CSI/CNI drivers, node exporters,
   control-plane static pods) are FP (`infra-need`); the paper reports
   the infra/app split from taxonomy v2.
8. **`SA_TOKEN_AUTOMOUNTED`** is FP where the workload's function requires
   API access (controllers, operators, cert managers); TP for application
   workloads with no API need.
9. **`SECRET_LITERAL_ENV`** excludes `*_FILE` paths, secret-name
   references, password-policy settings, and obvious placeholders.

## Evidence-absent rows (class D, 7 rows)

Rows whose flagged property cannot be observed in the source file — images
injected by kustomize overlays (K8S-113, 207, 236, 371) and one row whose
object could not be located (K8S-189) — are **excluded from precision
denominators, with the count and reason disclosed** in the paper's methods.
They are not counted as TP or FP. If the kustomize bases are rendered in a
future corpus revision, these rows are re-labeled then.

## Reliability design (corrected)

- The ~10% hidden duplicates measure **intra-rater consistency**
  (test–retest) of the pre-labeler: 44/44 duplicate groups agreed. This is
  reported as intra-rater consistency only — not inter-rater reliability.
- **Inter-rater reliability** is measured on the blinded subset in
  `results/kappa_subset/`: 30 unique-content rows spanning all 25 rules,
  labeled by the author *before* seeing the pre-labels. Agreement is
  reported as Cohen's κ (author vs AI pre-labels) via
  `scripts/score_kappa.py`, with a target of κ ≥ 0.7; every disagreement
  is adjudicated and logged.
- The author's verification pass over the full sample remains the ground
  truth of record (blank = accept pre-label). Divergence-list rows are
  verified first, since they carry the standard-sensitive decisions.

## Reporting

Per rule: precision = TP / (TP + FP) over decided rows, with Wilson 95%
CIs; `IMG_NO_DIGEST` and `DEPRECATED_API` reported as separate tiers per
amendments 1 and 4. Adjusted prevalence = per-rule precision × population
findings. Fixture-tagged findings are excluded from prevalence numerators
and denominators and reported as their own line; example-tagged findings
are reported with and without, as a sensitivity analysis.
