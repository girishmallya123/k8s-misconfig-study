# RQ3 — Auditing the auditors: tool coverage matrix (Helm arm)

Input (identical for all tools): `corpus/helm` — 151 rendered charts, 2,616 documents,
402 workloads, 595 containers. Our rule engine found 4,372 findings on this input.
Tools: kube-linter 0.8.3, kubeaudit 0.22.2, Polaris 10.2.5, Checkov 3.3.30, all default settings.
Raw outputs: `results/tools/`. Counts below are each tool's reported findings for the named
check; "—" means the tool has no check for the practice. Units differ by tool (per-container,
per-pod, per-resource) — that divergence is itself a result, see Finding 2.

| Our rule (our findings) | kube-linter | kubeaudit | Polaris | Checkov |
|---|---|---|---|---|
| SA_TOKEN_AUTOMOUNTED (357) | — | AutomountSATokenTrueAndDefaultSA: 91 (narrower: default SA only) | — | CKV_K8S_38: 356 |
| IMG_NO_DIGEST (576) | — | — | — (pullPolicyNotAlways: 517 is a proxy, not pinning) | CKV_K8S_43: 391 — **only tool that checks** |
| IMG_UNTAGGED (14) | merged ↓ | ImageTagMissing: 14 (exact) | tagNotSpecified: 55 (merged) | merged ↓ |
| IMG_LATEST (41) | latest-tag: 55 (= 41 latest + 14 untagged, exact reconciliation) | — | merged ↑ | CKV_K8S_14: 51 (merged) |
| RES_NO_CPU_LIMIT (502) | unset-cpu-requirements: 416 (merged w/ requests) | LimitsCPUNotSet: 76; LimitsNotSet: 421 (pod-level units) | cpuLimitsMissing: 411 | CKV_K8S_11: 343 |
| RES_NO_MEM_LIMIT (479) | unset-memory-requirements: 479 (**exact**) | LimitsMemoryNotSet: 53; LimitsNotSet: 421 | memoryLimitsMissing: 388 | CKV_K8S_13: 327 |
| RES_NO_REQUESTS (414) | merged into unset-* | — (no requests auditor) | cpuRequestsMissing: 335; memoryRequestsMissing: 334 | CKV_K8S_10: 177; CKV_K8S_12: 178 |
| SEC_NO_SECCOMP (363) | — | SeccompProfileMissing: 239 | linuxHardening: 298 (composite) | CKV_K8S_31: 240 |
| SEC_APE_NOT_DISABLED (309) | privilege-escalation-container: 34 | APE Nil: 295 + True: 10 = 305 | privilegeEscalationAllowed: 309 (**exact**) | CKV_K8S_20: 201 |
| SEC_ROOT_NOT_PREVENTED (293) | run-as-non-root: 280 | RunAsNonRootNil: 254 (+CSCRoot: 21) | runAsRootAllowed: 280 | CKV_K8S_23: 162 (narrower) |
| SEC_RUN_AS_ROOT_EXPLICIT (23) | merged ↑ | RunAsUserCSCRoot: 21 + PSCRoot: 1 = 22 | merged ↑ | merged ↑ |
| SEC_PRIVILEGED (27) | privileged-container: 27 (**exact**) | PrivilegedTrue: 26 | runAsPrivileged: 27 (**exact**) | CKV_K8S_16: 22 |
| SEC_CAPABILITY_ADDED (15) | drop-net-raw-capability: 15 (NET_RAW only) | CapabilityAdded: 58 (any capability) | insecureCapabilities: 313 (incl. not dropping) | CKV_K8S_37: 205 (incl. defaults) |
| SEC_DANGEROUS_CAPABILITY (12) | unsafe-sysctls/docker-sock: ~2 | CapabilityShouldDropAll: 11 | dangerousCapabilities: 12 (**exact**) | CKV_K8S_39 (SYS_ADMIN): 8 |
| HOST_NETWORK (23) | host-network: 23 (**exact**) | NamespaceHostNetworkTrue: 23 (**exact**) | — (hostPortSet: 3 is a different property) | CKV_K8S_19: 23 (**exact**) |
| HOST_PID (9) | host-pid: 9 (**exact**) | NamespaceHostPIDTrue: 9 (**exact**) | — | CKV_K8S_17: 9 (**exact**) |
| HOST_IPC (1) | host-ipc: 1 (**exact**) | NamespaceHostIPCTrue: 1 (**exact**) | — | CKV_K8S_18: 1 (**exact**) |
| REL_NO_LIVENESS_PROBE (303) | liveness-port: 26 — checks probe *port validity*, NOT missing probes | — | livenessProbeMissing: 211 | CKV_K8S_8: 157 |
| REL_NO_READINESS_PROBE (296) | readiness-port: 24 — same caveat | — | readinessProbeMissing: 205 | CKV_K8S_9: 144 |
| SECRET_LITERAL_ENV (29) | env-var-secret: 14 | — | sensitiveContainerEnvVar: 30 | CKV_K8S_35: 84 (broader) |
| SECRET_COMMITTED (122) | — | — | — | — (**no tool flags committed Secret objects**) |
| RBAC_WILDCARD_VERBS (91) | — | — | — (RBAC checks target exec/cluster-admin patterns) | CKV_K8S_49: 29 (partial, merged w/ resources) |
| RBAC_WILDCARD_RESOURCES (64) | — | — | — | merged ↑ |
| RBAC_CLUSTER_ADMIN_BINDING (7) | — | — | clusterrolebindingClusterAdmin: 21 + rolebindingClusterAdminRole: 10 (broader) | CKV2 graph checks: ~4–23 (partial) |
| DEPRECATED_API (2) | deprecated-service-account-field: 3 (a field, not an API version) | DeprecatedAPIUsed: 4 | — | — |

Approximate taxonomy coverage (25 rules; partial = ½): kube-linter ~11, kubeaudit ~11,
Polaris ~13, Checkov ~16. **No tool covers more than about two-thirds of observed practices.**

## Checks the tools have that our taxonomy v1 lacks (reverse gaps)

- **readOnlyRootFilesystem not set** — flagged by ALL four (kube-linter 365, Polaris 365,
  kubeaudit 352 Nil + 10 False, Checkov 237). Our engine has no such rule → taxonomy v2 adds it.
- AppArmor annotation missing — kubeaudit's single largest output (587); legacy annotation semantics.
- Default namespace usage — Checkov's single largest output (CKV_K8S_21: 1,560); no other tool checks it.
- imagePullPolicy != Always — Polaris's largest output (517); Checkov CKV_K8S_15: 328.
- High-UID requirement — Checkov CKV_K8S_40: 321.
- Operational checks (kube-linter): dangling services, missing PDBs, anti-affinity, Job TTL.

## Findings

1. **The most common risky practice is nearly unchecked.** Unpinned image digests affect 97.5%
   of Helm workloads (576 container findings); exactly one of four tools (Checkov) has a check
   for it, and it reports only 391. Committed Secret objects (122) and wildcard RBAC (155
   findings) are invisible to all four tools at default settings.
2. **Same check, wildly different counts on identical input.** "CPU limits missing" yields
   76 (kubeaudit) / 343 (Checkov) / 411 (Polaris) / 416 (kube-linter) against 502 container-level
   cases. The spread comes from counting units (pod vs container vs resource) and nil-vs-false
   semantics — so a "compliance rate" from any single tool is largely an artifact of the tool.
3. **Tools agree exactly on the explicit, diverge on the implicit.** Privileged containers
   (26–27 everywhere), hostNetwork (23 ×3 tools), hostPID (9), hostIPC (1) reconcile almost
   perfectly. Divergence concentrates in default-insecure configurations — fields left unset —
   which is where most of the corpus's risk actually lives.
4. **Most tool output is absence-of-hardening, not presence-of-danger.** kubeaudit's output is
   dominated by "Nil" findings (field not set). Practitioners facing thousands of such findings
   per scan have no severity gradient to prioritize by — a plausible mechanism for the alert
   fatigue that leaves the underlying defaults unchanged.
5. **Name collisions mislead.** kube-linter's "liveness-port" does not detect missing liveness
   probes (kubeaudit has no probe check at all); Polaris's "tagNotSpecified" merges untagged
   and latest. Cross-tool comparisons that match checks by name overstate agreement.

*Method note:* all tools ran with default check sets, as a practitioner would install them.
Counts extracted from raw JSON in `results/tools/`; per-check counts reproducible from those files.
Kubeaudit is formally deprecated by Shopify (binary prints a deprecation notice) yet remains
widely referenced — part of the ecosystem picture, retained deliberately.
