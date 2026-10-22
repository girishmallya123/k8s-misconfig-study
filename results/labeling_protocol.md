# Labeling protocol — validation sample v2

> **SUPERSEDED (2026-10-22).** This v2 protocol is retained for provenance;
> the AI pre-labels were produced under it (see the addendum below). The
> governing protocol is now `results/labeling_protocol_v3.md`. Note also
> the correction in v3's reliability section: the 44/44 duplicate agreement
> recorded in the addendum is intra-rater consistency, not inter-rater
> reliability; the inter-rater measurement lives in `results/kappa_subset/`.

**Purpose.** Estimate the rule engine's precision: are the things it flags actually
misconfigurations? Reviewers will ask; this sample is the answer.

**Sample.** `labeling_sample_v2.csv` (~450 rows): all privileged-container and
cluster-admin-binding findings, plus a stratified random sample (seed 42) of every
other rule across source groups (helm / production / example / fixture).

**How to label.** For each row, open the source file, find the named workload, and judge
the flagged property in context:

- **TP** (true positive) — the manifest really has the misconfiguration the rule names.
- **FP** (false positive) — the rule fired but the manifest is actually fine (e.g. the
  value is set at pod level and inherited, the "secret" is an obvious placeholder like
  `changeme`, the privileged container is a documented infra agent that requires it —
  mark these FP with a note, they refine the taxonomy rather than shame it).
- **unsure** — cannot tell from the manifest alone; write why in `notes`.

**Rules of the road.**
- Label what the manifest says, not what you guess the deployment looks like.
- One row = one judgment; don't let neighboring rows influence you (rows are shuffled).
- ~10% of rows are duplicated with different IDs for agreement checking (Cohen's kappa);
  label every row independently.
- Budget: at 30–60 seconds a row this is a 4–6 hour pass; split it across sessions and
  note where you stopped in the lab notebook.

**After labeling.** Precision per rule = TP / (TP + FP). Rules under ~90% precision get
fixed or redefined in taxonomy v2, and the paper reports per-rule precision alongside
prevalence — that pairing is what makes the numbers citable.

---

## Addendum (2026-10-21): AI pre-labeling pass

The 457-row v2 sample has been pre-labeled by the research assistant (Muse) to reduce
the author's verification burden. Method, disclosed here for the paper's methods section:

- For every row, an evidence packet was extracted from the flagged manifest
  (`scripts/extract_packets.py` → `results/labeling_packets.jsonl`): the flagged
  object's security contexts, resources, probes, image reference, service-account
  settings (including the SA object's own automount flag), RBAC rules, and decoded
  Secret value previews.
- Each row was judged against the protocol standard above (label the manifest in
  context), with a one-line written justification per row
  (`results/labeling_sample_v2_prelabelled.csv`, columns `prelabel`, `prelabel_reason`).
- **Author verification protocol:** the author reviews each row's pre-label and reason;
  a blank `your_label` accepts the pre-label as final; any disagreement is recorded in
  `your_label` (+ `your_notes`). Final ground truth = `your_label` where present, else
  `prelabel`. The author remains the labeler of record; pre-labels are a draft.
- Consistency: the ~10% hidden duplicates were labeled blind; pre-labels agreed on
  44/44 duplicate groups.
- Known extraction caveat: Argo CD install bundles contain two same-named ClusterRoles
  (a scoped variant and a wildcard variant); the packet extractor took the first match
  for four rows (K8S-064/209/261/290). Those four were verified by hand against the
  source documents.

Pre-label outcome (draft numbers; final precision waits for author verification):
328 TP / 122 FP / 7 unsure — overall draft precision ≈ 73%. Rules with draft precision
under ~65% need taxonomy-v2 redefinition: SECRET_COMMITTED (12% — empty placeholder
Secrets dominate; require non-empty credential material), SEC_CAPABILITY_ADDED (24% —
least-privilege drop-ALL+NET_BIND_SERVICE patterns and default-set caps must be
excluded), HOST_NETWORK (25%) / HOST_PID (21%) / HOST_IPC (59%) — control-plane static
pods and node agents need an infrastructure class, SEC_PRIVILEGED (61% — same infra
split), SECRET_LITERAL_ENV (40% — exclude *_FILE paths, secret-name references,
password-policy settings, and placeholders).
