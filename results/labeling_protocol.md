# Labeling protocol — validation sample v2

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
