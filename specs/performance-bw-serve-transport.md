# Performance: Replace subprocess-per-operation with `bw serve` HTTP transport

Aligns with https://github.com/kjanat/kp2bw/issues/1

**Status:** Ready for task breakdown\
**Effort:** L (1-2 days)\
**Date:** 2026-02-23

## Problem Statement

**Who:** Anyone migrating a KeePass database with >50 entries\
**What:** The tool spawns a separate `bw` CLI subprocess for every vault
operation (create item, create folder, upload attachment). The `bw` CLI is a
Node.js app with ~200-500ms startup overhead per invocation. All operations
are sequential.\
**Why it matters:** For 500 entries with 100 attachments, the tool takes ~190
seconds. ~95% of that is subprocess startup overhead, not actual work.\
**Evidence:** Profiling the main loop in `convert.py:475` — each `bw create
item` call at `bitwardenclient.py:170` takes ~300ms, of which ~200-500ms is
Node.js cold start.

## Proposed Solution

Replace the subprocess-per-operation architecture with a **hybrid** approach:

1. **`bw import bitwardenjson`** — Bulk-create all entries (folders + items) in
   a single subprocess call by writing a Bitwarden JSON export file and
   importing it. This eliminates N subprocess calls for entry creation.

2. **`bw serve`** — Start a persistent `bw serve` process (Koa HTTP server on
   `localhost`) for operations that can't be batched: attachment uploads,
   deduplication queries, collection management. HTTP requests to a running
   server have ~5-20ms latency instead of ~300ms per subprocess.

3. **Async parallel attachment uploads** — Use `asyncio` + `httpx.AsyncClient`
   to upload attachments concurrently (bounded by semaphore) via the
   `POST /attachment` endpoint.

This is a **breaking change** (v3). The old subprocess transport is removed
entirely.

### Expected Performance

| Phase                  | Current (subprocess) | New (import + serve)   |
| ---------------------- | -------------------- | ---------------------- |
| Init                   | 5 subprocesses ~1.5s | 1 serve start ~2s      |
| Create 500 items       | 500 x ~300ms = 150s  | 1 import call ~2s      |
| Upload 100 attachments | 100 x ~400ms = 40s   | 25 x ~200ms (4x) = ~5s |
| **Total**              | **~190s**            | **~9s**                |

~21x speedup.

## Scope & Deliverables

| #  | Deliverable                              | Effort | Depends On |
| -- | ---------------------------------------- | ------ | ---------- |
| D1 | `BitwardenServeClient` — serve lifecycle | M      | -          |
| D2 | `bw import` batch entry creation         | M      | D1         |
| D3 | Serve-based operations (folders, items)  | M      | D1         |
| D4 | Async parallel attachment uploads        | M      | D3         |
| D5 | Dedup via serve (list items/folders)     | S      | D1         |
| D6 | Collection support via serve             | S      | D3         |
| D7 | CLI changes + dependency updates         | S      | D1-D6      |
| D8 | E2E test updates                         | S      | D7         |

## Non-Goals (Explicit Exclusions)

- **Direct Bitwarden API client** — requires implementing full E2E encryption
  (AES-256-CBC-HMAC, RSA key exchange, PBKDF2/Argon2 key derivation). Not
  worth the effort/maintenance for a migration tool.
- **Backward compatibility with old transport** — clean break, no `--legacy`
  flag. Users must have `bw` CLI with `serve` command (available since ~v1.12).
- **The `custom_protected` accumulation bug** (convert.py:350-394) — separate PR.
- **Card/identity/secure note types** — currently unsupported, stays that way.

## Architecture

### Process Lifecycle

```txt
kp2bw start
  |
  v
bw serve --port <random> --hostname localhost
  |  (wait for GET /status -> "unlocked")
  |
  v
POST /unlock { password: "..." }
  |
  v
POST /sync
  |
  v
Phase 1: Build Bitwarden JSON export file in memory
  |       - Folders array with synthetic UUIDs
  |       - Items array with folderId cross-refs
  |       - All fields: login, TOTP, custom fields, passkeys, URIs
  |
  v
Phase 2: bw import bitwardenjson /tmp/kp2bw-import-XXXX.json  (one subprocess)
  |       - Handles folders + items in one batch
  |       - Temp file deleted immediately after
  |
  v
Phase 3: POST /sync  (refresh vault state after import)
  |
  v
Phase 4: GET /list/object/items  (get item IDs for attachment mapping)
  |       - Match imported items by name+folder to get server-assigned IDs
  |
  v
Phase 5: Parallel attachment uploads via POST /attachment?itemid=<id>
  |       - asyncio.Semaphore(4) bounded concurrency
  |       - httpx.AsyncClient multipart file upload
  |
  v
bw serve process terminated (SIGTERM + wait)
```

### Module Structure

```txt
src/kp2bw/
  bitwardenclient.py    -> REPLACED (remove subprocess transport)
  bw_serve.py           -> NEW: BitwardenServeClient (HTTP transport)
  bw_import.py          -> NEW: build + write Bitwarden JSON, run bw import
  convert.py            -> MODIFIED: use new client, async attachment phase
  cli.py                -> MODIFIED: new flags, httpx dep
  exceptions.py         -> UNCHANGED
```

## Data Model

### Bitwarden JSON Import File

The import file follows the `bitwardenjson` format exactly as defined by the
Bitwarden client source code:

```python
@dataclass
class ImportFile:
    encrypted: bool = False
    folders: list[ImportFolder]
    items: list[ImportItem]


@dataclass
class ImportFolder:
    id: str  # synthetic UUID (uuid4), only for cross-ref within file
    name: str  # folder path e.g. "Root/Finance/Banks"


@dataclass
class ImportItem:
    # Cross-ref fields (reset by importer, only used for folder binding)
    id: str | None = None
    organizationId: str | None = None
    collectionIds: list[str] | None = None
    folderId: str | None  # matches ImportFolder.id

    type: int  # 1=Login (only type we produce)
    name: str
    notes: str | None
    favorite: bool = False
    reprompt: int = 0

    fields: list[ImportField] | None = None
    login: ImportLogin | None = None

    # Unused — always None
    secureNote: None = None
    card: None = None
    identity: None = None
```

**Note:** The importer resets `id`, `organizationId`, and `collectionIds` on
import. The UUIDs in `folderId` are only used internally to bind items to
folders within the file.

### `bw serve` API Contracts

All responses follow:

```python
# Success
{"success": True, "data": {...}}

# Error
{"success": False, "message": "...", "data": None}
```

Key endpoints used:

| Endpoint                  | Method | Request                | Response `data`          |
| ------------------------- | ------ | ---------------------- | ------------------------ |
| `/status`                 | GET    | -                      | `{status: "unlocked"}`   |
| `/unlock`                 | POST   | `{password: str}`      | `{raw: "<session_key>"}` |
| `/sync`                   | POST   | -                      | `{title: "Syncing..."}`  |
| `/list/object/items`      | GET    | `?folderid=X`          | `{data: [item, ...]}`    |
| `/list/object/folders`    | GET    | -                      | `{data: [folder, ...]}`  |
| `/object/item`            | POST   | item JSON body         | `{id: "uuid", ...}`      |
| `/object/folder`          | POST   | `{name: str}`          | `{id: "uuid", ...}`      |
| `/attachment?itemid=<id>` | POST   | multipart `file` field | updated item             |
| `/object/org-collection`  | POST   | collection JSON        | `{id: "uuid", ...}`      |

**Auth model:** Process-level. Must be logged in before `bw serve` starts.
`POST /unlock` unlocks the vault. No per-request tokens/headers needed.

**Origin protection:** `bw serve` blocks requests with `Origin` header by
default. We don't set `Origin` from `httpx`, so this is not an issue.

**Request size:** Default koa-bodyparser limit is 1MB for JSON bodies.
Attachment uploads via multer have no explicit limit.

## API/Interface Contract

### `BitwardenServeClient`

```python
class BitwardenServeClient:
    """Manages a bw serve process and provides HTTP API access."""

    def __init__(self, password: str, org_id: str | None = None) -> None:
        """Start bw serve, unlock vault, sync, load existing state."""
        ...

    def close(self) -> None:
        """Terminate the bw serve process."""
        ...

    def __enter__(self) -> Self: ...
    def __exit__(self, *exc: object) -> None: ...

    # --- Sync operations (used during import phase) ---

    def sync(self) -> None:
        """Force vault sync."""

    def list_folders(self) -> dict[str, str]:
        """Return {name: id} mapping of all folders."""

    def list_items(self) -> list[dict[str, Any]]:
        """Return all vault items."""

    def create_folder(self, name: str) -> str:
        """Create folder, return its ID. Cached — no-op if exists."""

    def create_item(self, item: dict[str, Any]) -> str:
        """Create single item via HTTP, return its ID."""

    def create_org_collection(self, name: str, org_id: str) -> str:
        """Create org collection, return its ID. Cached."""

    # --- Async operations (attachment phase) ---

    async def upload_attachment(
        self,
        item_id: str,
        filename: str,
        data: bytes,
    ) -> None:
        """Upload one attachment via multipart POST."""

    async def upload_attachments_parallel(
        self,
        items: list[tuple[str, list[tuple[str, bytes]]]],
        max_concurrency: int = 4,
    ) -> None:
        """Upload all attachments with bounded parallelism."""
```

### `build_import_file`

```python
def build_import_file(
    entries: dict[str, tuple[str | None, dict[str, Any]]],
) -> dict[str, Any]:
    """Build a Bitwarden JSON import dict from parsed entries.

    Returns dict ready for json.dumps() with 'folders' and 'items' arrays.
    Assigns synthetic UUIDs for folder cross-references.
    """


def run_import(filepath: Path) -> None:
    """Execute `bw import bitwardenjson <filepath>` as subprocess."""
```

## Deduplication Strategy

Current dedup: download all vault items, check if name exists in folder.

New dedup (two modes):

1. **Pre-import dedup** — Before building the import file, query
   `GET /list/object/items` and `GET /list/object/folders` via serve. Build
   the same `{folder_name: set[item_name]}` index. Exclude already-existing
   entries from the import file. Uses `set` instead of `list` for O(1) lookup.

2. **Post-import attachment mapping** — After import, sync and list items
   again. Match imported items by `(name, folderId)` to recover server-assigned
   IDs for attachment uploads.

## Acceptance Criteria

- [ ] `bw serve` process starts, health-checks, and terminates cleanly
- [ ] 500 entries import completes in <15 seconds (vs ~190s current)
- [ ] Attachments upload in parallel with bounded concurrency
- [ ] Existing e2e test (Vaultwarden) passes with new transport
- [ ] Duplicate entries are skipped (same behavior as current)
- [ ] Folders, TOTP, custom fields (text + hidden), passkeys, URIs with match
      types all import correctly
- [ ] `bw serve` process is terminated on error/interrupt (atexit + signal)
- [ ] No sensitive data (password, session key) logged
- [ ] Organization + collection flow works via serve
- [ ] Temp import file is deleted immediately after use
- [ ] Works with both Bitwarden official and Vaultwarden servers

## Test Strategy

| Layer       | What                       | How                                      |
| ----------- | -------------------------- | ---------------------------------------- |
| Unit        | Import file generation     | Build import dict, assert JSON schema    |
| Unit        | Dedup logic (set-based)    | Mock item list, verify exclusions        |
| Unit        | Serve client HTTP calls    | httpx mock transport / respx             |
| Integration | Full migration flow        | Existing Vaultwarden e2e test            |
| Integration | Attachment parallel upload | Vaultwarden e2e with attachment fixtures |
| Manual      | Passkey migration          | KeePassXC DB with FIDO2 entries          |

## Risks & Mitigations

| Risk                                           | Likelihood | Impact | Mitigation                                                     |
| ---------------------------------------------- | ---------- | ------ | -------------------------------------------------------------- |
| `bw serve` not available in user's bw CLI      | Low        | High   | Document min version. Check `bw serve --help` at startup.      |
| Port conflict on 8087                          | Medium     | Low    | Use random available port via `find_free_port()`.              |
| `bw serve` process leak on crash/SIGINT        | Medium     | Medium | `atexit.register`, context manager, signal handler.            |
| `bw import` creates duplicates on re-run       | Medium     | Medium | Pre-import dedup removes existing entries from import file.    |
| Import file >1MB (koa-bodyparser limit)        | Low        | Low    | Import uses subprocess not HTTP. Only serve requests hit this. |
| Concurrent attachment uploads cause errors     | Low        | Medium | Start with concurrency=4, make configurable. Retry on 5xx.     |
| `bw import` field format drift across versions | Low        | High   | Pin to `bitwardenjson` format. Test in CI against real bw.     |

## Trade-offs Made

| Chose                        | Over                          | Because                                                  |
| ---------------------------- | ----------------------------- | -------------------------------------------------------- |
| `bw serve` HTTP transport    | Direct Bitwarden API          | No crypto implementation needed. Same CLI compatibility. |
| `bw import` for batch items  | Individual HTTP POST per item | One subprocess vs N HTTP requests. 2s vs 7.5s.           |
| Full asyncio for attachments | ThreadPoolExecutor            | Cleaner concurrency model, native httpx async support.   |
| Clean break (no legacy)      | Dual transport                | Less code. Migration tool — run once, don't need compat. |
| Process-level auth           | Per-request session tokens    | That's how bw serve works. Simpler.                      |

## Dependencies

| Package     | Purpose                    | New? |
| ----------- | -------------------------- | ---- |
| `httpx`     | HTTP client (sync + async) | Yes  |
| `pykeepass` | KeePass DB reading         | No   |

## Open Questions

- [ ] Does `bw import` handle the `reprompt` field? Need to test. -> Owner: implementation
- [ ] Max concurrency for attachment uploads before Vaultwarden rate-limits? -> Owner: e2e testing
- [ ] Should we support `--concurrency` CLI flag for attachment parallelism? -> Owner: UX decision

---

## Deliverables (Ordered)

1. **D1: `BitwardenServeClient` lifecycle** (M) — Start/stop `bw serve`,
   health check, unlock, sync, port selection, cleanup handlers.
   - Depends on: -
   - Files: `src/kp2bw/bw_serve.py` (new)

2. **D2: `bw import` batch creation** (M) — Build Bitwarden JSON from parsed
   entries, write temp file, execute `bw import bitwardenjson`, delete temp
   file. Handle folder cross-references with synthetic UUIDs.
   - Depends on: D1 (needs serve for pre-import dedup)
   - Files: `src/kp2bw/bw_import.py` (new)

3. **D3: Serve-based CRUD operations** (M) — HTTP wrappers for create folder,
   create item, list items, list folders. Folder cache. Used as fallback for
   items that can't go through import (org items with collections).
   - Depends on: D1
   - Files: `src/kp2bw/bw_serve.py`

4. **D4: Async parallel attachment uploads** (M) — `asyncio` +
   `httpx.AsyncClient` with semaphore-bounded concurrency. Multipart file
   upload to `POST /attachment?itemid=<id>`.
   - Depends on: D3 (needs item ID mapping)
   - Files: `src/kp2bw/bw_serve.py`

5. **D5: Dedup via serve** (S) — Query existing items/folders, build
   `dict[str, set[str]]` index, filter import file.
   - Depends on: D1
   - Files: `src/kp2bw/bw_serve.py`

6. **D6: Collection support** (S) — `POST /object/org-collection` via serve.
   Template fetch via `GET /object/template/org-collection`.
   - Depends on: D3
   - Files: `src/kp2bw/bw_serve.py`

7. **D7: CLI + convert.py integration** (S) — Wire new client into
   `convert.py`. Update `cli.py` flags. Add `httpx` dependency. Remove old
   `bitwardenclient.py`.
   - Depends on: D1-D6
   - Files: `src/kp2bw/convert.py`, `src/kp2bw/cli.py`,
     `src/kp2bw/bitwardenclient.py` (delete), `pyproject.toml`

8. **D8: E2E test updates** (S) — Update Vaultwarden e2e test for new
   transport. Add attachment test fixtures if missing.
   - Depends on: D7
   - Files: `tests/e2e_vaultwarden_test.py`

## Key Technical Decisions

- **`bw serve` over direct API**: No client-side encryption implementation needed
- **`bw import` for batch items**: Eliminates N subprocess calls; one call creates all entries
- **Synthetic UUIDs for import cross-refs**: Importer resets all IDs; UUIDs only bind items to folders within the file
- **`set` for dedup**: O(1) lookup vs current O(K) list membership
- **Random port**: Avoids conflicts; `bw serve --port <n>`
- **No `/import` endpoint in serve**: Import must be a subprocess call (confirmed from bw CLI source)
