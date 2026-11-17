# Duplicate and overlap evidence

`duplicate_report` (074) examines selected files with `matching_options`.
`overlap_report` (075) adds peers and a split specification. Deliberately choose
supported exact/normalized matching; surface, token and annotation equality
answer different questions. Normalization can collapse distinct original data.

Retain pair evidence: corpus/file, sentence/draft locator, matching unit,
original text/hash and split membership. Distinguish within-corpus duplicates,
cross-corpus overlap and train/dev/test leakage. Missing split membership stays
unknown rather than receiving an invented partition.

State the denominator and direction: a fraction of the left corpus, right corpus
or unique shared units differs. Deduplication changes the statistic. Overlap alone
does not prove plagiarism or intent; common sources, boilerplate and short
utterances can explain matches. Deletion/resplitting needs a separate reviewed
plan preserving source and license records.
