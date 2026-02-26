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

| Task                   | Location                  | Notes                                           |
| ---------------------- | ------------------------- | ----------------------------------------------- |
| Add/adjust CLI flags   | `src/kp2bw/cli.py`        | `main()` and argument parser are here           |
| Change import behavior | `src/kp2bw/convert.py`    | Top-level `convert()` flow and migration phases |
| Tune dedup/idempotency | `src/kp2bw/bw_serve.py`   | Existing item index + batch create behavior     |
| Attachment behavior    | `src/kp2bw/bw_serve.py`   | Async upload path and multipart logic           |
| Map KeePass fields     | `src/kp2bw/convert.py`    | Entry/custom field/TOTP/passkey mapping         |
| API type definitions   | `src/kp2bw/bw_types.py`   | Hand-written TypedDicts supplementing codegen   |
| Regenerate API types   | `scripts/generate-bw-types.sh` | Run after editing `specs/vault-management-api.json` |
| Error contract         | `src/kp2bw/exceptions.py` | Keep custom exception taxonomy central          |

## CONVENTIONS

- Use module logger (`logger = logging.getLogger(__name__)`), never root logger calls.
- Keep sensitive values out of logs (no raw `bw` commands/output, no session/password values).
- Raise project exceptions (`BitwardenClientError`, `ConversionError`) instead of bare `Exception`.
- Keep relative imports for local modules (`from .exceptions import ConversionError`).
- Python 3.14 comma-form multi-except is valid; do not rewrite it to tuple form just for style.

## ANTI-PATTERNS

- Reintroducing subprocess-per-op transport for new work.
- Logging decrypted vault content or credential-bearing command strings.
- Breaking idempotency by bypassing existing-item dedup checks.
- Changing conversion behavior without updating e2e expectations in `tests/e2e_vaultwarden_test.py`.

## NOTES

- `bw_serve.py` is the active transport path; `bw_import.py` and `bitwardenclient.py` are legacy/reference.
- Maintain behavior parity for `kp2bw.cli:main` and `python -m kp2bw`.
- Dedup index is org-scoped when `--bitwarden-org` is set: `_build_dedup_index()` passes `organization_id=self._org_id` to `list_items()`, which appends `organizationId` as a query param to `/list/object/items`. When `org_id` is `None` (personal vault), no filter is applied and all vault items are indexed. This prevents personal vault entries from shadowing an empty org vault during migration.
- When a fixed `--bitwarden-collection` is given, the dedup index is further scoped to that collection via `collection_id`. Items in other collections are treated as new.
- `_bw_api_types.py` is generated — run `bash scripts/generate-bw-types.sh` after spec changes. CI checks for drift via `codegen-check.yml`.
