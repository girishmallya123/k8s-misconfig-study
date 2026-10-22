# Labeling protocol — K8s misconfiguration study validation sample

**Sample:** `labeling_sample_pilot_v1.csv` — 302 findings (all high-severity/rare findings +
stratified slice of common rules), each linked to its source file.
Fill `label_TP_FP_unsure` (TP / FP / UNSURE) and `reviewer_notes` per row.

**Source-role context:** `results/file_tags.json` maps each GitHub-arm source file to
`production` / `example` / `fixture` (Helm-arm rows: infer from chart path; `templates/tests/`
and `ci/` dirs are fixtures). The tag informs context but does not decide the label —
label the *finding on its merits*, and note the tag's influence in `reviewer_notes`.

## The labeling question

Not "did the engine fire correctly?" — for absence-type rules the engine counts a missing
hardening control as a finding by design (documented per rule; those prevalence figures are
upper bounds). The question is:

> **Is this a genuine, exploitable hardening gap in a realistic deployment of this workload?**

- **TP** — yes, a real gap an attacker or an outage could ride through.
- **FP** — the finding is benign by design: infra agent that needs the privilege, placeholder
  or fixture content, a standard-practice pattern, or a parser artifact.
- **UNSURE** — can't tell from the manifest alone (say what would settle it).

**Structured notes format** (keep it terse):
`role:infra-agent` for system DaemonSets/controllers (CNI, CSI, node exporter, log/metrics agents);
`fp_reason:<code>` with codes: `infra-need`, `placeholder`, `fixture`, `standard-practice`,
`parser-artifact`, `not-exploitable`; free text for anything else.

## Rule-by-rule decision table

Grounded in the taxonomy v1 engine (`scripts/analyze.py`) — what it checks, then how to judge.

| Rule | Engine checks | TP | FP |
|---|---|---|---|
| SEC_PRIVILEGED | `securityContext.privileged == true` | Default | `role:infra-agent` — DaemonSet/system component (CNI, CSI, node exporter); `fixture` |
| SEC_RUN_AS_ROOT_EXPLICIT | `runAsUser: 0` (container or pod) | Default | `role:infra-agent` only |
| SEC_APE_NOT_DISABLED | `allowPrivilegeEscalation != false` (missing counts) | Runs as root, or adds caps, or writable rootfs with setuid risk | Non-root + no added caps + dropped caps — escalation path absent (`not-exploitable`) |
| SEC_ROOT_NOT_PREVENTED | `runAsNonRoot != true` (container or pod) | Same test as APE: escalation path real | Non-root image + no caps (`not-exploitable`) |
| SEC_DANGEROUS_CAPABILITY | `capabilities.add` includes SYS_ADMIN / ALL / NET_ADMIN | Default | `role:infra-agent` with genuine need |
| SEC_CAPABILITY_ADDED | any other added capability | Cap not needed for the workload's function | Clearly functional (e.g. `NET_BIND_SERVICE` on a server binding a low port) |
| SEC_NO_SECCOMP | no `seccompProfile.type` at container or pod level | Default — real absence | Essentially never; labeler can't see cluster defaults, so this stays an upper bound — note it |
| HOST_NETWORK / HOST_PID / HOST_IPC | `hostNetwork/hostPID/hostIPC == true` | Default | `role:infra-agent` node-level DaemonSets (`infra-need`) |
| SA_TOKEN_AUTOMOUNTED | `automountServiceAccountToken != false` | App workload with no API need | Controller/operator that genuinely talks to the API server |
| RES_NO_CPU_LIMIT / RES_NO_MEM_LIMIT / RES_NO_REQUESTS | absent limits/requests | `production`-tagged, long-running | `example` / `fixture` / one-shot Job or test manifest |
| REL_NO_LIVENESS_PROBE / REL_NO_READINESS_PROBE | no probe on Deployment/ReplicaSet/StatefulSet/DaemonSet/Pod | Serves traffic or long-runs without probes | One-shot, debug, example, or fixture manifests (Jobs/CronJobs aren't evaluated by the engine) |
| IMG_UNTAGGED | image has no tag (implicit `:latest`) | Always — mutable reference, drift risk | Never |
| IMG_LATEST | explicit `:latest` tag | Always — mutable reference, drift risk | Never |
| IMG_NO_DIGEST | image not `@sha256:`-pinned | Only when untagged/`:latest` (covered above) | Explicit tag without digest = standard industry practice (`standard-practice`); record as hardening-gap, not misconfiguration |
| SECRET_COMMITTED | committed `Secret` objects | Real-looking credentials in data/stringData | Empty data, `changeme`/placeholder/test values, templated `{{ }}` values; `fixture` dirs (`placeholder`, `fixture`) |
| SECRET_LITERAL_ENV | env var whose name matches `password\|passwd\|secret\|token\|api[-_]?key\|access[-_]?key` with a literal `value:` | Real-looking literal secret | Placeholder/empty/templated value (`placeholder`) |
| RBAC_WILDCARD_VERBS / RBAC_WILDCARD_RESOURCES | `*` in rule verbs/resources | Default | Scoped to test/e2e/fixture namespaces |
| RBAC_CLUSTER_ADMIN_BINDING | binding to `cluster-admin` | Default — flag the subject | Genuine admin controller, with `role:infra-agent` |
| DEPRECATED_API | apiVersion in the removed-API set | Always — factual rot signal | `parser-artifact` only. Report separately as *manifest rot*, not misconfiguration prevalence |

## Workflow

1. **Batch in 50s** — ~1–2 min/row, 302 rows ≈ 5–10 hours total. Don't marathon it; drift kills agreement.
2. **Blind overlap first:** both labelers independently label the same 30 rows (S001–S030), then compare.
   Target Cohen's κ ≥ 0.7. Adjudicate every disagreement, sharpen this doc where it was ambiguous,
   *then* do the remaining 272.
3. **Fixtures stay labeled, get excluded from prevalence** — report the fixture contamination rate
   separately (it's a finding about the ecosystem, and it documents the kubescape/regolibrary caveat).
4. **Infra-agent split:** every `role:infra-agent` finding feeds taxonomy v2's infra-vs-app split —
   this is what defuses the "privileged is more common in Helm" reviewer attack (memo §"New threads").

## Calibration math (after labeling)

Per rule: adjusted prevalence = (TP / n_sampled_for_rule) × (population findings for rule).
Report Wilson 95% CIs. Fixture-tagged findings excluded from the numerator/denominator and reported
as their own line. `example`-tagged findings: report prevalence both with and without.

## What this unlocks

- **Taxonomy v2** — infra-vs-app split, digest sub-categories, fixture exclusion; honest effect sizes.
- **RQ3 ground truth** — the TP/FP labels become the reference set for scoring kube-linter, kubeaudit,
  Polaris, and checkov: per-tool precision/recall against human judgment is the "auditing the auditors"
  comparison, and it's stronger than tool-vs-tool agreement.
