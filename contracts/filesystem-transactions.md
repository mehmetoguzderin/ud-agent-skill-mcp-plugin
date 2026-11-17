# Filesystem transaction contract

A workspace grant binds native filesystem access to the opened workspace identity.
Plans identify their expected inputs and bytes. Apply checks those identities and
hashes again, stages candidates privately, validates them independently, and
records recoverable progress before replacing authorized files.

Locks coordinate cooperating UD processes. Hash and identity checks detect stale
inputs; they do not provide portable compare-and-swap against an uncooperative
writer. Replacement is atomic for an individual file when the selected filesystem
supports the required primitive. A multi-file edit can be interrupted between
files and must be recovered using its journal; it is not a globally atomic commit.
A retry with the same operation identity reconciles recorded results rather than
applying the edit twice. Recovery checks ownership and the recorded original and
candidate identities before restoring or completing work.

Metadata preservation is a required capability, including relevant permissions,
extended metadata and durable flush behavior. Unsupported metadata does not become
a successful edit with a loss warning: the affected apply is blocked.

On Windows, the ordinary-user NTFS route first probes Transactional NTFS (TxF).
When available, transacted writes preserve the same file object, including its
security descriptor and alternate streams. Deleted originals remain in opaque,
exclusively owned backups in their directory for identity-preserving recovery.
The non-TxF metadata route requires the process token's existing privileges to read
and preserve the complete security/stream metadata. It does not elevate the
process or change machine policy. An unavailable filesystem/API or missing
privilege blocks the affected edit when no supported preservation route remains.
Microsoft advises alternatives to TxF and says that it may be absent from future
Windows versions. [Microsoft's TxF guidance](https://learn.microsoft.com/en-us/windows/win32/fileio/about-transactional-ntfs)

Portable policy tests and cross-built binaries do not certify Windows behavior.
Its ACL, stream, filesystem, flush, interruption and cancellation cases must also
execute on an actual supported Windows provider before native acceptance passes.
