# Attachment checkpoints

Keep a checkpoint when migrating a vault with attachments:

```sh
kp2bw vault.kdbx --checkpoint ./migration-checkpoint.json
```

Run the same command again after an interruption. Use the same KeePass file, account, server and organization or
collection selection. `KP2BW_CHECKPOINT` supplies the path when the flag is omitted.

The checkpoint records attachment identities, hashes, sizes and verified destination revisions. An unchanged rerun
checks remote metadata without downloading or uploading attachment bodies. A changed remote revision causes the files to
be read and checked again. Destination edits remain protected.

New files uploaded with this option receive a stable suffix before the extension, such as `report
(kp2bw-<transaction-id>).pdf`. This identifies an interrupted upload even when the CLI never returned its attachment ID.
Existing associated files keep their names. The suffix remains after successful migration.

After an interrupted replacement, kp2bw checks the uploaded bytes and saves their association before removing the old
copy. It can reuse a completed upload or retry a slot whose body is confirmed missing. Ambiguous files, unreadable files
and changes to the old copy are preserved and reported as failures.

Keep the source attachment unchanged until its interrupted upload has been reconciled. Changing it while an upload is
pending stops recovery for that item; restore the source version used by the interrupted run, finish that run, then
apply the new source change.

A missing or corrupt checkpoint causes verification from the vault instead of trusting cached results. A unique
completed transaction file can be recovered by checking its bytes. An incomplete or ambiguous file without a valid
checkpoint is preserved for manual inspection. A checkpoint belonging to a different source or destination is rejected;
use a separate path for each migration.

The file contains no passwords, sessions, attachment bodies or plaintext filenames. It still contains identifiers and
content hashes, so keep it private. Writes replace the file atomically, and a lock prevents concurrent processes from
using the same checkpoint. Preserve it between runs to retain verified results.
