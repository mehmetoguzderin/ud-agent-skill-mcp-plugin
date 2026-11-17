# Registered rules and proposals

`language_rules_report` (085) inspects language and peers under the declared
context. Separate registered values from observed annotations: observed values
can be invalid, and registered values can have no instances in selected data.

`language_rule_change_plan` (086) compares current rules with explicit
`proposed_rules_path`. Inspect additions/removals, hashes and unresolved choices.
A local plan is not upstream modification or linguistic approval.

`language_rule_impact_report` (087) evaluates the proposal on selected
`affected_treebank_paths`. Current/proposed contexts are independent immutable
inputs; modifying the original rules invalidates the comparison. Report newly
failing/passing and unchanged evidence with scope and context hashes. Fewer
errors alone do not establish linguistic correctness.

Prepare accepted contexts through the coordinator's authorized context route.
Retain mappings, proposal hashes and bounded affected scope. Ordinary analysis
must not fetch moving rules or load project code as rule data.
