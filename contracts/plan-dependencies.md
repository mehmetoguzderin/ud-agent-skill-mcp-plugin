# Applying a selected dependency closure

`plan_apply` executes only `selected_action_ids`. An unselected dependency is
accepted when the broker can derive its complete file effect from the action
and prove that effect already holds: create/replace bytes match the declared
content and SHA-256, a deletion is explicitly observed absent, or a rename's
source is absent and its destination contains the exact expected bytes.
Dependencies of those actions are checked as well. Unknown IDs and cycles reject.

The broker reads every relevant file through the granted workspace identity. It
adds present bytes and a version-one state receipt, including explicit absence
observations, to the immutable input snapshot. The private transport binds the
receipt to that snapshot. Application arguments cannot install this authority.
The worker verifies the exact plan, selection, receipt and staged file bytes.
The host independently derives the conditions again, recaptures the inputs,
and accepts candidates only for selected actions.
For selected literal file and text actions, it also derives the expected final
bytes from the frozen plan/pre-state and rejects omitted or substituted effects.

Apply rechecks these read conditions under the workspace transaction lock after
candidate validation, before and after each publication, and before completion.
Checks use the expected final bytes for files already applied by the transaction.
Recovery also rechecks around its durability replay. The journal retains read
conditions for interrupted commit reconciliation. A stale condition prevents a
completed result; conflicting recovery preserves the journal and external state.
As with other transactions, uncooperative external writers can race a file
fingerprint check: this does not add a filesystem-wide compare-and-swap.

Structural edits, context preparation and text replacements can use a prior
host-issued completed-batch receipt in the existing private recovery record.
The receipt binds the exact plan bytes and selected action set, workspace/root
identity, original snapshot, completed transaction/request identity and complete
final output closure. File commits require completed, passing independent
candidate validation. Admission rereads the private record and journal and checks
the journal's recomputed request identity, still-current outputs and workspace
validation inputs. Legacy records without
the additive receipt provide no completion authority.

A dependency on any member admits the completed batch as a unit. All batch
outputs must remain current, including outputs of members that the new request
does not depend on directly. Composed actions on the same file are supported:
the proof concerns completed batch execution and its final state, not the continued
presence of every intermediate effect. Newly selected actions still undergo their
own precondition checks, fresh candidate validation and transaction checks.

Context publication is verified separately against the immutable resource bytes,
rule hashes, context identity and exact rule action. A context-only receipt reports
publication verification, not a nonexistent file transaction or corpus validation.
Resource identity/availability is rechecked during dependent publication and
recovery. Publication does not activate rules or replace an explicit context
selection. Expired, removed or changed resources do not supply proof.
Context-only receipts certify only batches consisting entirely of context
actions; a publication cannot certify an omitted text or structural edit.
Multiple context actions are matched in admitted dependency order.

Without this durable proof, matching a
caller-authored `postconditions` map or an `after_sha256` alone does not establish
that a structural/text action produced those bytes. These cases fail closed; include
the dependency in the selection when it should actually execute. No unselected
action is implicitly applied and no linguistic validation is inferred from
file fingerprints.

Rename aliases must agree exactly when both spellings are present; source and
destination must not collide under the portable path comparison. Host write
scope uses only these canonical paths, never every supplied alias.
