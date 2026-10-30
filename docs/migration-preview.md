# Preview a migration

Read your KeePass database and inspect the conversion without opening Bitwarden:

```sh
kp2bw vault.kdbx --preview
kp2bw vault.kdbx --preview json > migration-plan.json
```

The preview uses the same source conversion as migration. It lists source UUIDs, destination item types, native field
paths, custom-field and passkey counts, previous-password counts, and generated or original attachment names and byte
totals. Field values and attachment contents are excluded from both output formats.

Use the same migration options you intend to run, including template/SSH mappings, tag filters, history archival and
oversized-secret handling. The JSON document includes `schema_version`, per-entry details, source group omissions and
aggregate counts. A blocking conversion problem produces a nonzero exit status while retaining the other entries in the
report.

To compare against the destination, reuse your authenticated CLI profile:

```sh
kp2bw vault.kdbx --preview json --preview-target
```

This additionally requests the Bitwarden password and reads the selected vault. Organization and fixed-collection scope
use the same `-o` and `-c` options as migration. The report distinguishes creation, updates, unchanged items, protected
edits and blocked entries. Reconciliation writes go to temporary in-memory snapshots; no items, folders, collections or
attachments are written by the preview. Comparing attachments can download their bytes for verification.

Source-only attachment names describe allocation without a destination. Target inspection accounts for existing
attachment associations and names. Both modes preserve the source database.

Use `--entry-id UUID` to preview one source entry. `--item-id UUID` additionally requires `--preview-target` to resolve
its source association. References can read dependencies, but the plan includes only the selected entry.

With `--checkpoint PATH`, target inspection reads the saved checkpoint and simulates recovery in memory. It does not
create a lock or write the checkpoint. Completed uploads are checked before predicting another upload, and incomplete
slots are removed only from the simulation. The report uses the same transaction filenames as migration. Without target
inspection, `filename_final: false` marks names whose account-dependent checkpoint suffix cannot yet be calculated.

Review omissions as well as blockers. Group notes and settings, icons and auto-type settings have no direct destination
representation. Full historical records are omitted unless `--archive-history` is enabled. Invalid passkeys, unresolved
references, oversized fields that cannot be preserved and ambiguous destination matches are reported instead of being
presented as complete conversions.

Target inspection checks organization item-type and personal-vault policies, native SSH availability, known attachment
entitlement and organization storage limits. Missing policy metadata is reported as a blocker. Free storage is not
exposed by the synchronized CLI metadata, so the report leaves it unknown. A successful preview does not reserve storage
or prevent another client from changing the vault before migration. Review the result, then rerun your command without
the preview flags to migrate.
