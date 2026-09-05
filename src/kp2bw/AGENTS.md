# SOURCE PACKAGE KNOWLEDGE BASE

## OVERVIEW

Runtime package for CLI argument handling, KeePass parsing, Bitwarden conversion, and transport.

## STRUCTURE

```tree
src/kp2bw/
├── cli.py              # CLI parsing, prompts, env handling, run mode selection
├── convert.py          # Conversion orchestrator and entry transformation pipeline
├── bw_serve.py         # bw serve process lifecycle + HTTP CRUD + attachment upload
├── otp.py              # KeePass/PPS OTP custom fields -> Bitwarden login.totp (pure, no I/O)
├── uri_mapping.py      # KeePass URL syntax -> Bitwarden login URIs + match modes
├── bw_types.py         # Hand-written TypedDict types (supplements generated types)
├── _bw_api_types.py    # Auto-generated from specs/vault-management-api.json (DO NOT EDIT)
├── _console.py         # Shared Rich Console instance (stderr)
├── exceptions.py       # BitwardenClientError, ConversionError
├── __main__.py         # python -m kp2bw handoff
└── __init__.py         # __version__ from installed metadata
```

## WHERE TO LOOK

| Task                   | Location                       | Notes                                               |
| ---------------------- | ------------------------------ | --------------------------------------------------- |
| Add/adjust CLI flags   | `src/kp2bw/cli.py`             | `main()` and argument parser are here               |
| Change import behavior | `src/kp2bw/convert.py`         | Top-level `convert()` flow and migration phases     |
| Tune dedup/idempotency | `src/kp2bw/bw_serve.py`        | Existing item index + batch create behavior         |
| Attachment behavior    | `src/kp2bw/bw_serve.py`        | Async upload path and multipart logic               |
| Map KeePass fields     | `src/kp2bw/convert.py`         | Entry/custom field/TOTP/passkey mapping             |
| OTP field resolution   | `src/kp2bw/otp.py`             | Field-name schemes, decoding, `otpauth://` emission |
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
- Breaking idempotency: a re-run with no KeePass changes must issue no `PUT` and upload no attachment
  (`_content_differs` / upload-if-missing gate this).
- Changing conversion behavior without updating e2e expectations in `tests/e2e_vaultwarden_test.py`.

## NOTES

- Maintain behavior parity for `kp2bw.cli:main` and `python -m kp2bw`.
- Existing-item sync (`--update` / `--no-update`, `KP2BW_UPDATE`, default on, `Converter(update_existing=...)`):
  `convert._reconcile_existing_item()` diffs a matched login item via `_content_differs()` and, when changed, `PUT`s a
  payload built by `_build_update_payload()` (preserves id/favorite/folder/org, unions collectionIds, keeps a
  Bitwarden-side passkey absent from KeePass). Attachments are reconciled by content, not just name: a file the item
  lacks is uploaded, and one whose bytes changed but kept its filename is re-uploaded (`_attachment_content_differs()`
  downloads via `get_attachment()` and compares; an unreadable existing copy is treated as unchanged to avoid data
  loss). The stale copy is deleted only after its replacement uploads (upload-then-delete), so `upload_attachments()`
  returns failed `(item_id, filename)` pairs and the deletion is skipped when its replacement upload failed. Uploads are
  deduped per `(item_id, filename)`. Content and attachment failures are non-fatal and counted; `convert()` returns the
  failure count, and the CLI exits non-zero when it is non-zero. `--no-update` restores skip-only behavior (collection-
  membership sync still applies).
- Oversize custom fields (value over `MAX_BW_ITEM_LENGTH`, 10k) are offloaded to a `<key>.txt` attachment instead of an
  inline field (mirrors long notes → `notes.txt`), decided in `_add_bw_entry_to_entries_dict()`. Three carve-outs: a
  consumed OTP key is already in `login.totp`, so its raw field is dropped as a dedup (no warning); a hidden OTP secret,
  passkey attribute, or KeePass-protected field (`custom_protected`) survives nowhere else, so it is **not** written to
  a plaintext attachment by default — it is warned-and-dropped to avoid silent data loss. `--include-oversize-secrets`
  (`KP2BW_INCLUDE_OVERSIZE_SECRETS`, `Converter(include_oversize_secrets=...)`, default off) opts into offloading those
  secrets to their attachment too.
- Dedup keys on a **stable identity**, not `(folder, title)`. Every migrated item carries a plain-text `KP2BW_ID` custom
  field holding the source KeePass entry UUID (an identifier, not a secret — hence text, not hidden; stamped in
  `_add_bw_entry_to_entries_dict`, read by `bw_serve.item_kp2bw_id`, and excluded from `_fields_signature` so it never
  triggers a spurious update). `_build_dedup_index()` builds `_by_uuid` (stamped items) plus `_legacy_by_folder_name`
  (unstamped **login** items only). Per entry, `convert` matches by UUID (`get_item_by_uuid`); failing that it claims
  one unstamped legacy item by `(folder, name)` (`claim_legacy_item`) and `force_update`s it to backfill the stamp;
  failing that it creates a new item. This stops distinct same-titled entries from collapsing onto one item (data loss)
  and keeps re-runs idempotent across title/folder edits. The legacy adoption is a one-time path for vaults imported
  before stable identity.
- Manual-edit protection (issue #30, `--force-update` / `KP2BW_FORCE_UPDATE`, `Converter(force_update=...)` →
  `self._force_update_all`): every written item carries a `KP2BW_SYNC` plain-text field holding
  `_item_sync.content_signature(item)` — a sha256 over name, notes, custom fields (including `linkedId`), and login
  credentials/URIs (including URI order and `match`); managed stamps are excluded. Pre-3.8.1 stamps remain valid over
  their original field/URI coverage and are upgraded on a safe write; ambiguous edits to newly covered values fail
  closed. When content differs **and** the item was user-edited **and** not
  `force_update`/`_force_update_all`, it returns `"protected"` (no PUT, attachments skipped) instead of clobbering.
  kp2bw's own writes restamp, so they never self-trip; an unstamped (legacy/first-run) item returns `False` and updates
  normally to establish the stamp. The signature mechanism is deliberate over comparing Bitwarden's `revisionDate` to a
  client timestamp — the server bumps `revisionDate` *after* kp2bw generates a stamp, so a timestamp compare would
  false-trip every kp2bw-written item. The `protected` count is reported in the summary. Tests: `protect_edits_test.py`.
- `--strip-ids` (`KP2BW_STRIP_IDS`, default off) is the finalize-mode inverse of the stamps above: it short-circuits
  migration entirely (`main()` returns before any KeePass read or password prompt) and only touches Bitwarden, removing
  the `KP2BW_ID` **and** `KP2BW_SYNC` fields from every in-scope item via `_run_strip_ids` (`cli.py`) →
  `strip_field_from_items(*field_names)` (`bw_serve.py`, one full `update_item` `PUT` per stamped item). Scope mirrors a
  migration (`-o`/`-c`), so only items kp2bw could have stamped are touched. It is **irreversible** and degrades future
  re-runs (they fall back to `(folder, name)` matching), so an interactive run confirms first (skippable with
  `-y`/`KP2BW_YES`); a declined prompt exits `0` (clean abort), Ctrl+C exits `130`. Re-runnable: a second pass finds
  nothing.
- `--migrate-uris` is a Bitwarden-only legacy upgrade. Before folding URL/app fields, it verifies any existing
  `KP2BW_SYNC` against a freshly fetched full item and skips mismatches; unstamped legacy items remain eligible. It
  rechecks the outgoing full-object body against another fetch immediately before the `PUT`. Every transformed item is
  restamped, and a repeated pass writes nothing.
- `--metadata` (default on) folds the KeePass metadata Bitwarden has no native slot for — **tags and expiry** — into a
  single readable **YAML** `KP2BW_META` text field (`_build_metadata_field`, via PyYAML
  `safe_dump(allow_unicode=
  False)` so control chars and the U+0085/2028/2029 line-break code points are escaped, not
  silently corrupted), omitted when an entry has neither (so most items get no metadata field at all).
  `Created`/`Modified` timestamps are **not** migrated: Bitwarden manages its own creation/revision dates and the API
  cannot backdate them (a client-supplied `creationDate` is ignored on create and rejected on update), so the originals
  had no native home and were dropped rather than clutter every item.
- OTP lives in `otp.py`, which is pure: `resolve_otp()` takes `entry.otp` plus the raw custom properties and returns an
  `OtpMigration` (the `login.totp` value, the keys to drop, the keys to keep **hidden**, and warning strings the caller
  logs). Precedence: a non-blank `entry.otp` URI wins outright and the secret fields are then kept hidden rather than
  consumed; otherwise the TOTP fields are read. A default-config Base32 secret is emitted as the bare canonical secret,
  anything else (other encoding, non-default digits/period/algorithm) as a self-describing `otpauth://` URI. HOTP has no
  Bitwarden target: its secret is warned about and kept hidden.
- Field *names* are a `_TotpScheme` (secret decoders in priority order, the Base32 key, length/period keys, optional
  algorithm key), selected per call by `resolve_otp(..., totp_pps=...)`. The KeePass scheme reads
  `TimeOtp-Secret-Base32`/`-Hex`/`-Base64`/`TimeOtp-Secret` plus `TimeOtp-Length`/`-Period`/`-Algorithm`; the Pleasant
  Password Server scheme (`--totp-pps` / `KP2BW_TOTP_PPS` / `Converter(totp_pps=...)`, issue #45) reads `TOTPSecret`
  (always Base32) plus `TOTPDigits`/`TOTPPeriod` and has no algorithm key, so `DEFAULT_ALGORITHM` (SHA-1) applies. The
  schemes **replace** each other for reading: only the active one is decoded and consumed. Hiding is not scheme-scoped -- `_ALL_SECRET_KEYS` spans **both** schemes plus HOTP, so a `TimeOtp-Secret-*` field under `--totp-pps` (or a
  `TOTPSecret` field without it) is carried over as a **hidden** field instead of a visible one, upholding the module
  invariant that no OTP secret is ever written in the clear. Config keys (`*-Length`/`Digits`, `*-Period`,
  `TimeOtp-Algorithm`) hold no secret, so the inactive scheme's stay ordinary custom fields. Tests: `tests/otp_test.py`.
- Custom properties are read by `convert._read_entry_custom_properties()` directly from each entry's `<String>`
  children. Do not replace this with `Entry.custom_properties` or dynamic XPath: supported PyKeePass versions
  interpolate custom keys into XPath. The single traversal returns both values and `Protected=True` keys so normal and
  REF-created items share hidden/oversize-secret behavior.
- A credential-matching REF alias merges only losslessly representable content: deduplicated URIs and a missing or
  semantically equivalent `login.totp` resolved through `resolve_otp()`. Conflicting TOTP, distinct referents, or other
  migratable alias content creates a separate item. Sibling aliases resolve in UUID order so conflicting TOTP handling
  is independent of XML order. Every successful merge refreshes `KP2BW_SYNC` after its final URI/TOTP mutation. A
  matching-content re-run repairs stale sync stamps written before REF restamping existed; the legacy shadow separately
  replays the historical DFS/XML order so deterministic fresh ordering does not reject untouched old output.
- Dedup is org-scoped when `--bitwarden-org` is set and collection-scoped when a fixed `--bitwarden-collection` is
  given: `_build_dedup_index()` / `list_items()` pass `organization_id` / `collection_id`. Personal vault (both `None`)
  indexes all visible items.
- `bw serve` teardown is **port-based** on Windows: a shim-launched serve runs as a `node` grandchild that `taskkill /T`
  does not reliably reap, so `terminate_serve(port=)` / `close()` also kill whatever still `LISTEN`s on the serve port
  (`parse_listening_pids` → `_kill_port_listeners`). Without this, orphaned serves accumulate and deadlock the shared
  `bw` app-data on later runs.
- A full DEBUG log is always written to a per-user file (`_configure_logging` in `cli.py`; `%LOCALAPPDATA%/kp2bw/logs`,
  override `KP2BW_LOG_FILE` / `KP2BW_LOG_DIR`) independent of console verbosity. `bw serve` HTTP errors carry the
  response body via `format_http_error` (no more opaque `HTTP 400`).
- `_bw_api_types.py` is generated — run `bash scripts/generate-bw-types.sh` after spec changes. CI checks for drift via
  `codegen-check.yml`.
