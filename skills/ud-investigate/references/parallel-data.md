# Parallel material and concordance

`parallel_corpus_report` (079) uses selected files, peer treebanks and an explicit
alignment specification. Establish source/target roles. Sentence, language,
passage and token identities are different keys; equal text is not proof of all
mappings. Keep one-to-many/many-to-one alignments explicit.

`bible_passage_concordance` (080) uses supported passage conventions. Preserve
book/chapter/verse and source locations, report unmatched/duplicate passages,
segmentation differences and missing metadata. Do not invent passage keys from
arbitrary sentence IDs.

Compare annotations only over the documented aligned population and report
excluded/unaligned material separately. Projection requires an explicit plan;
alignment does not license copying heads, features, empty nodes or MWTs blindly.

`sentence_batch_extract` (058) exports a selected subset to an authorized output.
Retain its selection specification and fingerprints, respect recorded data
licenses, and avoid exporting entire peer corpora for a few evidence sentences.
