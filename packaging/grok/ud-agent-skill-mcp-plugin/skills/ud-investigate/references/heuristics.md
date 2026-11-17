# Interpret heuristic evidence

`script_composition_report` (070) measures selected script composition; mixing can
reflect borrowing, names, transliteration or errors. `proper_name_sequences`
describes annotations, not entity gold. `english_relative_clause_classify` (071)
is language-specific: keep unmatched/ambiguous cases rather than transferring it
to other languages as a universal classifier.

Feature agreement should report matches, differences and missing evidence within
the relation scope. A mismatch can be grammatical and missing annotation is not
automatically a negative example. Heuristics need linguistic context before a
normative rule or repair follows.

`enhanced_graph_report` (076) and `enhanced_edge_explanations` (077) concern
explicit enhanced edges/empty nodes. Keep basic/enhanced graphs distinct. An
explanation is not permission to delete edges. `enhanced_empty_node_collapse_plan`
(078) proposes a lossy transformation: inspect its explicit specification,
reference mappings and loss report before application.

Label heuristics, include representative counterexamples and denominators, and
preserve unknown classifications. A single raw count cannot rank treebank
quality. Incomplete execution cannot establish absence of a phenomenon.
