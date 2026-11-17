# Explicit split and merge maps

Operations 099–102 require the resulting annotated sentences and reference
mapping, not just a new surface form or boundary. Inspect source rows and use the
discovered `annotation_map` schema. It supports `id_mapping`, `created`, explicit
resulting `sentences`, decision declarations and unresolved choices.

Typed sentences contain `sent_id`, `text`, `comments` and complete `rows`. Word
rows specify form/lemma/POS/features/MISC, basic head/label and enhanced edges.
Empty rows specify an anchor and enhanced edges; MWT rows specify components,
form and MISC. The alternate `conllu` representation also requires its supported
explicit decision declarations. Read the actual schema before constructing a map;
a partial row does not implicitly preserve missing annotation.

Map each affected source identity to target identity lists using the operation's
source/target convention. Account for deletions, one-to-many splits, many-to-one
merges, basic dependents, enhanced incident edges, empty-node anchors, MWT spans,
custom references and collisions. Keep unresolved decisions visible.

`token_split` needs replacement words and attachment decisions; `tokens_merge`
needs the resulting word and redirected references. `tree_split` needs new IDs
and every cross-boundary edge decision; `trees_merge` needs a coherent basic tree
and remapped special/enhanced rows. In all cases decide surface spacing/text and
sentence/document/paragraph comments. The supplied `boundary_policy` executes
preservation, transfer, movement, copying or dropping; choose only the requested
semantics.

`needs_annotation` is an incomplete proposal, not an applied edit. Present missing
choices, obtain them, regenerate a preview and validate the complete candidate.

## Complete preview example

The authored [token split request](../assets/token-split.json) includes exact
source bytes, a complete request and independently expected candidate bytes.
It splits `can't` into `can` and `not`, explicitly chooses each annotation and
keeps the original surface through a newly created MWT. It is an example of
decisions supplied by the caller, not a linguistic rule to apply automatically.

Map keys/targets use `sent_id#row_id`, for example `a#2` maps to `["a#2","a#3"]`.
Every original row must appear, including unchanged or special rows. The new MWT
`a#2-3` is listed in `created`; ordinary split mappings must match replacement
word forms and order, so the MWT is not inserted into that word's target list.
Dependent basic/enhanced heads are redirected to the explicit new word IDs.

Replace the example working-tree path and inspect actual fingerprints before
using it on another file. Decide whether a real request preserves the original
surface via an MWT or changes text/spacing to separate words. Neither choice is
implied by “preserve annotations.” Preview first and inspect its map/diff;
applying requires the reviewed candidate and independent validation scope.
