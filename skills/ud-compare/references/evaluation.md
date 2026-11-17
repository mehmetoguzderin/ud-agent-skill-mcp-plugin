# Evaluation roles and units

`predictions_evaluate` (081) uses `gold_file_paths` and `prediction_file_paths`.
Confirm pairing and compatible text/token alignment. Use the pinned official
scorer and retain metric names, raw counts and denominator definitions. A scorer
failure or unmatched corpus is incomplete execution, not a zero or perfect score.

`annotation_pair_scores` (082) uses `reference_annotation_path` and
`comparison_annotation_path`. Label these roles. Pairwise annotation scores are
not automatically chance-corrected agreement; do not rename them kappa or imply
a missing metric was calculated.

Tokenization changes affect the comparable population. Report alignment and
excluded units with POS/feature/dependency scores. Aggregate numerators and
denominators then recompute ratios; an unweighted mean of per-file accuracy/F1
is a different statistic. Include selected paths, hashes and scorer/context
identity. Distinguish invalid data, low prediction quality and incomplete
execution. Local evaluation is not an official shared-task submission.

The pinned scorer supplies named token/word/annotation metrics, including UAS and
LAS; use the returned metric inventory rather than assuming every scorer version
supports the same optional enhanced metrics. Sentence counts alone cannot
determine any attachment score. Establish whether “100 predictions for 10 gold
sentences” means ten systems, unmatched extra sentences or another pairing.

No application operation promises a chance-corrected kappa calculation. If kappa
is explicitly requested, identify the paired raters, annotation units, categories
and joint observations/contingency table, then state this capability boundary.
Offer a separately agreed, transparent calculation from those supplied data;
never relabel pair scores or infer kappa from corpus sizes.
