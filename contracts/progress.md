# Request progress

Both declared MCP revisions support requested `notifications/progress` for
environment and domain tools. The notification preserves the caller's numeric
or string progress token. Calls without a token produce no progress messages.

The numbers describe completed coordinator phases, with a total of four:

| Progress | Meaning |
| --- | --- |
| 0 | Checking the runtime or setup prerequisites. |
| 1 | Preparing a required runtime, or assessing a setup dry run. |
| 2 | Runtime readiness was verified. |
| 3 | Executing the requested operation, or saving a verified runtime selection. |
| 4 | The operation and its owned cleanup finished successfully. |

Phases that do not apply are omitted. A completed readiness inquiry can report
`ready: false`; complete linguistic validation can report `passed: false`.
These are completed inquiries, so they can reach four. Execution rejection,
incomplete work and cleanup failure do not report terminal success. Progress
does not establish linguistic validity or native runtime certification.

Progress delivery is advisory. A rejected notification cannot replace a
completed result, trigger another edit/export, or hide an actual worker or
cleanup failure. Direct delivery waits at most 250 milliseconds per phase;
after delivery fails or exceeds that bound, further notifications for that
delivery channel are suppressed. Real cancellation interrupts a pending
pre-worker notification and releases the acquired lease before starting work.

Same-tool continuations retain the latest phase with the operation. A currently
waiting resume request receives that phase using its own token and can receive
later phases. Concurrent waiting requests have separate delivery subscriptions,
bounded to 64 per operation; additional polls still receive their actual tool
result. Subscriptions end when the RPC returns a pending or terminal result,
is cancelled, or its session closes. Background work does not start new
notifications to a returned request's token.

The pinned SDK does not expose cancellation of an already-issued notification
send. Such a send may settle or arrive after its RPC returns, times out or is
cancelled. It retains its original token; it is never relabeled as a resumed
request's notification. The ordering guarantee is that no new delivery is
started after the request subscription ends. Clients should correlate tokens
and ignore a late message for a request they have already closed. Late send
settlement cannot retain a worker lease or alter its recorded outcome.
