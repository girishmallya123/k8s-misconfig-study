# Blinded kappa subset — instructions

**Purpose.** Measure inter-rater reliability (author vs AI pre-labels) for
the v2 validation sample, per protocol v3 (`results/labeling_protocol_v3.md`).

**Contents.**
- `blind_sample.csv` — 30 rows spanning all 25 rules, drawn from
  unique-content rows (no hidden duplicates), seed 20261022
  (`scripts/build_fix_kit.py`).
- `packets.jsonl` — the evidence packet for each row (same extraction as
  the main sample).

**How to label (important: stay blind).**
1. Label every row in `blind_sample.csv` (`blind_label` = TP / FP /
   unsure, plus `blind_notes`) using the packet and, where needed, the
   source file — **before opening `results/labeling_sample_v2_prelabelled.csv`
   or `results/prelabels.json`**. Looking first turns this back into a
   verification pass and destroys the measurement.
2. Judge under protocol v3's per-rule tests.
3. When all 30 are filled, score it:
   `python3 scripts/score_kappa.py`
   It prints agreement %, Cohen's κ (target ≥ 0.7), the confusion matrix,
   and the disagreements with the AI's reasons, for adjudication.
4. Log the κ and adjudications in `LAB_NOTEBOOK.md`.

Budget: ~30 rows × 1–2 min ≈ 30–60 minutes.
