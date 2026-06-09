# SOURCE PACKAGE KNOWLEDGE BASE

## OVERVIEW

Runtime package for CLI argument handling, KeePass parsing, Bitwarden conversion, and transport.

## STRUCTURE

```tree
src/kp2bw/
├── cli.py              # CLI parsing, prompts, env handling, run mode selection
├── convert.py          # Conversion orchestrator and entry transformation pipeline
├── bw_serve.py         # bw serve process lifecycle + HTTP CRUD + attachment upload
├── bw_types.py         # Hand-written TypedDict types (supplements generated types)
├── _bw_api_types.py    # Auto-generated from specs/vault-management-api.json (DO NOT EDIT)
├── _console.py         # Shared Rich Console instance (stderr)
├── exceptions.py       # BitwardenClientError, ConversionError
├── __main__.py         # python -m kp2bw handoff
├── __init__.py         # __version__ from installed metadata
├── bw_import.py        # Legacy bw import JSON path (retained)
└── bitwardenclient.py  # Legacy subprocess wrapper (retained)
```

## WHERE TO LOOK

| Task                   | Location                       | Notes                                               |
| ---------------------- | ------------------------------ | --------------------------------------------------- |
| Add/adjust CLI flags   | `src/kp2bw/cli.py`             | `main()` and argument parser are here               |
| Change import behavior | `src/kp2bw/convert.py`         | Top-level `convert()` flow and migration phases     |
| Tune dedup/idempotency | `src/kp2bw/bw_serve.py`        | Existing item index + batch create behavior         |
| Attachment behavior    | `src/kp2bw/bw_serve.py`        | Async upload path and multipart logic               |
| Map KeePass fields     | `src/kp2bw/convert.py`         | Entry/custom field/TOTP/passkey mapping             |
| API type definitions   | `src/kp2bw/bw_types.py`        | Hand-written TypedDicts supplementing codegen       |
| Regenerate API types   | `scripts/generate-bw-types.sh` | Run after editing `specs/vault-management-api.json` |
| Error contract         | `src/kp2bw/exceptions.py`      | Keep custom exception taxonomy central              |

## CONVENTIONS

- Use module logger (`logger = logging.getLogger(__name__)`), never root logger calls.
- Keep sensitive values out of logs (no raw `bw` commands/output, no session/password values).
- Raise project exceptions (`BitwardenClientError`, `ConversionError`) instead of bare `Exception`.
- Keep relative imports for local modules (`from .exceptions import ConversionError`).
- Python 3.14 comma-form multi-except is valid; do not rewrite it to tuple form just for style.

## ANTI-PATTERNS

- Reintroducing subprocess-per-op transport for new work.
- Logging decrypted vault content or credential-bearing command strings.
- Breaking idempotency: a re-run with no KeePass changes must issue no `PUT`
  and upload no attachment (`_content_differs` / upload-if-missing gate this).
- Changing conversion behavior without updating e2e expectations in `tests/e2e_vaultwarden_test.py`.

## NOTES

- `bw_serve.py` is the active transport path; `bw_import.py` and `bitwardenclient.py` are legacy/reference.
- Maintain behavior parity for `kp2bw.cli:main` and `python -m kp2bw`.
- Existing-item sync (`--update` / `--no-update`, `KP2BW_UPDATE`, default on,
  `Converter(update_existing=...)`): `convert._reconcile_existing_item()` diffs
  a matched login item via `_content_differs()` and, when changed, `PUT`s a
  payload built by `_build_update_payload()` (preserves id/favorite/folder/org,
  unions collectionIds, keeps a Bitwarden-side passkey absent from KeePass).
  Attachments are reconciled by content, not just name: a file the item lacks is
  uploaded, and one whose bytes changed but kept its filename is re-uploaded
  (`_attachment_content_differs()` downloads via `get_attachment()` and compares;
  an unreadable existing copy is treated as unchanged to avoid data loss). The
  stale copy is deleted only after its replacement uploads (upload-then-delete),
  so `upload_attachments()` returns failed `(item_id, filename)` pairs and the
  deletion is skipped when its replacement upload failed. Uploads are deduped per
  `(item_id, filename)`. Content and attachment failures are non-fatal and
  counted; `convert()` returns the failure count, and the CLI exits non-zero when
  it is non-zero. `--no-update` restores skip-only behavior (collection-
  membership sync still applies).
- Oversize custom fields (value over `MAX_BW_ITEM_LENGTH`, 10k) are offloaded to
  a `<key>.txt` attachment instead of an inline field (mirrors long notes →
  `notes.txt`), decided in `_add_bw_entry_to_entries_dict()`. Three carve-outs:
  a consumed OTP key is already in `login.totp`, so its raw field is dropped as a
  dedup (no warning); a hidden OTP secret, passkey attribute, or KeePass-protected
  field (`custom_protected`) survives nowhere else, so it is **not** written to a
  plaintext attachment by default — it is warned-and-dropped to avoid silent data
  loss. `--include-oversize-secrets` (`KP2BW_INCLUDE_OVERSIZE_SECRETS`,
  `Converter(include_oversize_secrets=...)`, default off) opts into offloading
  those secrets to their attachment too.
- Dedup keys on a **stable identity**, not `(folder, title)`. Every migrated
  item carries a hidden `KP2BW_ID` custom field holding the source KeePass entry
  UUID (stamped in `_add_bw_entry_to_entries_dict`, read by
  `bw_serve.item_kp2bw_id`, and excluded from `_fields_signature` so it never
  triggers a spurious update). `_build_dedup_index()` builds `_by_uuid` (stamped
  items) plus `_legacy_by_folder_name` (unstamped **login** items only).
  Per entry, `convert` matches by UUID (`get_item_by_uuid`); failing that it
  claims one unstamped legacy item by `(folder, name)` (`claim_legacy_item`) and
  `force_update`s it to backfill the stamp; failing that it creates a new item.
  This stops distinct same-titled entries from collapsing onto one item (data
  loss) and keeps re-runs idempotent across title/folder edits. The legacy
  adoption is a one-time path for vaults imported before stable identity.
- Dedup is org-scoped when `--bitwarden-org` is set and collection-scoped when a
  fixed `--bitwarden-collection` is given: `_build_dedup_index()` /
  `list_items()` pass `organization_id` / `collection_id`. Personal vault
  (both `None`) indexes all visible items.
- `bw serve` teardown is **port-based** on Windows: a shim-launched serve runs as
  a `node` grandchild that `taskkill /T` does not reliably reap, so
  `terminate_serve(port=)` / `close()` also kill whatever still `LISTEN`s on the
  serve port (`parse_listening_pids` → `_kill_port_listeners`). Without this,
  orphaned serves accumulate and deadlock the shared `bw` app-data on later runs.
- A full DEBUG log is always written to a per-user file (`_configure_logging` in
  `cli.py`; `%LOCALAPPDATA%/kp2bw/logs`, override `KP2BW_LOG_FILE` /
  `KP2BW_LOG_DIR`) independent of console verbosity. `bw serve` HTTP errors carry
  the response body via `format_http_error` (no more opaque `HTTP 400`).
- `_bw_api_types.py` is generated — run `bash scripts/generate-bw-types.sh` after spec changes. CI checks for drift via `codegen-check.yml`.
