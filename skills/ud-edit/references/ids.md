# References and batch identities

A normal `tree_ref` has `file_path` and `sent_id`. Missing/duplicate IDs require
the inspected zero-based `ordinal` plus `fingerprint` draft locator. Never select
the first duplicate. A canonical `token_ref` nests the tree reference and ordinary
word `token_id`; existing schema-supported aliases remain compatible.

Keep IDs as strings: ordinary `"1"`, MWT `"1-2"`, empty node `"5.10"` and root
`"0"` have distinct meanings. Never parse empty IDs as floats. Use MWT/empty-node
operations for special rows and distinguish basic heads from enhanced heads.

Batch references resolve against the starting snapshot. Give a newly created
sentence a `temporary_id` such as `$copy`, then reference it in the same batch
with `{ "temporary_id": "$copy" }`. Temporary names are not persistent CoNLL-U
IDs. Inspect returned mappings after insertion/deletion/movement/reindexing;
do not calculate later references from intermediate client-side row positions.

Absent patch fields preserve annotations; empty FEATS/MISC replacements explicitly
clear them. Replacing enhanced dependencies differs from adding/removing one edge.
Preserve comments, custom annotation and bytes outside the changed scope. Unknown
reference-bearing annotations need a policy before a structural remap.
