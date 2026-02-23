<!--markdownlint-disable-file no-duplicate-heading-->

# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Docker Compose e2e infrastructure** -- `tests/Dockerfile.vaultwarden`,
  `tests/Dockerfile.test`, `tests/docker-compose.yml`, and `.dockerignore` for
  fully containerized Vaultwarden integration tests. Fixture data is COPY'd into
  the Vaultwarden image; the test image bundles Python 3.14, `uv`, `bun`,
  Node.js, and `@bitwarden/cli`.
- **`-d`/`--debug` flag** -- Separate debug verbosity level that includes
  third-party library logs (pykeepass, httpx). `-v` now shows kp2bw operational
  detail only (custom VERBOSE level at 15), `-d` enables full DEBUG for
  everything.
- **Custom VERBOSE logging level** -- `kp2bw.VERBOSE` (15) sits between DEBUG
  and INFO, matching PowerShell's Write-Verbose/Write-Debug distinction.
- **Pytest adapters for script tests** -- Added
  `tests/test_script_adapters.py` so `pytest` can collect and run script-style
  test modules while preserving `main()`-based direct execution.
- **CLI-output sanitization tests** -- Added
  `tests/bw_serve_sanitization_test.py` to verify secret redaction, whitespace
  normalization, and truncation behavior.

### Changed

- **CI workflow simplified** -- `integration-docker.yml` reduced to a single
  `docker compose up --build --abort-on-container-exit --exit-code-from test`
  invocation, replacing multi-step `bw` CLI setup.
- **CI build output collapsible** -- Docker image build phase wrapped in
  `::group::` markers so it collapses in GitHub Actions logs.
- **Regenerated TLS certs** -- Self-signed cert now includes `DNS:vaultwarden`
  SAN for Docker Compose service-name resolution.
- **`firstlevel` refactored out of BwItem dict** -- Internal collection-routing
  key now travels as a separate `EntryValue` tuple element instead of being
  smuggled inside the Bitwarden API payload dict.
- **`collectionIds` corrected to array** -- Now emits `[id]` or `[]` per the
  Bitwarden API spec, instead of a bare string or `None`.
- **`EntryValue` normalized to one tuple shape** -- Internal converter storage
  now always carries attachments as a list (empty when none), removing
  3-tuple/4-tuple branching and `type: ignore` indexing.
- **Test workflow documentation expanded** -- Added adapter-driven pytest
  commands and opt-in env flags for packaging/e2e script tests in `AGENTS.md`.

### Fixed

- **`bw serve` IPv6 binding** -- `--hostname localhost` caused Node.js/Koa to
  bind to `::1` (IPv6 loopback) while `httpx` connected to `127.0.0.1` (IPv4),
  resulting in a 60 s timeout. Changed to `--hostname 127.0.0.1`.
- **`bw serve` subprocess pipe stall** -- Removed `stdout=PIPE` from
  `_start_serve()`; stderr remains piped for crash diagnostics while stdout now
  inherits parent file descriptors. Removed dead `_read_output()` method that
  depended on piped streams.
- **Signal handler restore crash** -- `close()` could raise `TypeError` when
  restoring signal handlers that were `None` (C-installed handlers). Now guards
  against `None` before calling `signal.signal()`.
- **Third-party debug log spam** -- `-v` no longer sets root logger to DEBUG;
  pykeepass/httpx debug messages only appear with `-d`.
- **Deprecated `WEBSOCKET_ENABLED` env var** -- Removed from docker-compose.yml;
  silently ignored since Vaultwarden 1.29.
- **Dockerfile.test missing `pipefail`** -- Added `SHELL` directive so `curl`
  failures in pipe are not masked.
- **Root-level explicit collection assignment** -- Entries without a first-level
  KeePass group now still receive an explicitly configured Bitwarden
  collection ID.
- **Org collection create with missing org ID** -- `create_org_collection()` now
  short-circuits when no org ID is configured instead of attempting a POST with
  `organizationId: None`.
- **Attachment upload JSON parse failures** -- Non-JSON `/attachment` responses
  now raise `BitwardenClientError` with HTTP context instead of leaking decode
  exceptions.
- **`bw serve` response parse hardening** -- Core `_request()` now maps
  non-JSON responses to `BitwardenClientError`; dedup index also skips malformed
  item names safely.
- **Signal-ignore semantics** -- `_signal_handler()` now respects inherited
  `SIG_IGN` handlers instead of forcing process exit.
- **Sensitive stderr exposure in diagnostics** -- `bw unlock` and early
  `bw serve` stderr output is now sanitized (secret redaction + truncation)
  before logs/error messages are emitted.
- **E2E command output redaction** -- Integration helper now redacts
  `--session`/`--passwordenv` values and `--raw` command output in failure
  messages.

### Removed

- **Diagnostic `_smoke_test_bw_serve()`** -- Removed from e2e test; it launched
  `bw serve` with piped stdout (which also triggered the IPv6 binding issue) and
  blocked the test run.

## [3.0.0a1] - 2026-02-23

### Added

- **`bw serve` HTTP transport** -- New `BitwardenServeClient` in
  `bw_serve.py` manages a persistent `bw serve` process with HTTP API
  access, replacing the one-subprocess-per-operation model. Includes automatic
  port selection, health polling, vault unlock/sync, signal-safe cleanup, and
  `atexit` registration.
- **Batch import via `bw import`** -- New `bw_import.py` module builds
  Bitwarden-format JSON and invokes `bw import` for bulk item creation,
  dramatically reducing the number of subprocess calls.
- **Dedup index** -- `BitwardenServeClient` maintains an
  `O(1)` `dict[str | None, set[str]]` index of existing vault entries to
  skip duplicates without per-item API calls.
- **Async parallel attachment uploads** -- Attachments are uploaded concurrently
  via `asyncio` with a bounded semaphore (default 4) for backpressure.
- **Org collection CRUD with cache** -- `bw serve`-based collection
  creation/listing with an in-memory name-to-ID cache, avoiding repeated API
  round-trips.
- **`bw serve` availability guard in e2e test** -- `_assert_bw_serve_available()`
  pre-flight check before running the Vaultwarden integration test.
- **`httpx` runtime dependency** -- Added `httpx>=0.28.0` for the HTTP
  transport layer.

### Changed

- **4-phase migration architecture** -- `convert.py`
  `_create_bitwarden_items_for_entries()` rewritten: (1) partition entries,
  (2) bulk import, (3) post-import sync and ID recovery, (4) parallel
  attachment uploads.
- **Version bump to 3.0.0a1** -- Major version increment reflecting the
  breaking change from subprocess-per-item to `bw serve` transport.
- **100% docstring coverage** -- Added docstrings to all functions and methods
  across `convert.py`, `cli.py`, and `bitwardenclient.py`.

### Fixed

- **Signal handler init race** -- `_previous_sigterm` / `_previous_sigint`
  are now assigned before `_start_serve()` so that `close()` is safe to
  call at any point during `__init__` (e.g. when `_wait_for_ready` times
  out).
- **Duplicate item name ID lookup** -- Post-import ID recovery now collects all
  IDs per `(folder, name)` pair and pops them in order, so entries sharing the
  same name each get their own server-assigned ID for attachment uploads.
- **`bw serve` startup diagnostics** -- Captured stderr from the `bw serve`
  process and included it in timeout/crash error messages. Closed stdin via
  `subprocess.DEVNULL` to prevent blocking. Increased startup timeout from
  30 s to 60 s for CI headroom.
- **e2e test empty session token** -- `bw login` + separate `bw unlock --raw`
  returned an empty session on `@bitwarden/cli@2026.1.0`. Replaced with
  `bw login --raw` to capture the session in a single step; added
  lock-then-unlock retry fallback in `_get_session()`.
- **`bw import` command injection** -- `run_import` used `shell=True` with a
  format-string command; replaced with list-form `subprocess.check_output`
  (no shell).
- **`close()` double-call crash** -- `BitwardenServeClient.close()` was not
  idempotent; second call could restore stale signal handlers or raise on
  `_http.close()`. Added `_closed` guard.
- **Attachment upload fail-fast** -- `asyncio.gather` abandoned remaining
  uploads on first error; now uses `return_exceptions=True` to collect all
  failures before raising an aggregate error.

## [2.0.0] - 2026-02-23

### Fixed

- **Stubs missing runtime dependency** -- Added explicit `lxml>=6.0.2`
  dependency to `pykeepass-stubs`; previously only `types-lxml` was declared,
  leaving the runtime `lxml` import unsatisfied when the stubs package was
  installed standalone.
- **`except` clauses using Python 2 syntax** -- `except ValueError,
  binascii.Error` and `except ConversionError, KeyError, AttributeError` only
  caught the first exception type; the remaining names were silently
  misinterpreted as the exception variable. Fixed to tuple syntax
  `except (A, B)`.
- **Protected custom fields leaking across entries** -- `custom_protected` list
  was initialized once before the entry loop and accumulated field names from
  every entry, causing later entries to incorrectly treat same-named properties
  as protected. Now reset per entry.

## [2.0.0rc3]

### Added

- **CLI version flag** -- Added `-V` / `--version` to print installed `kp2bw`
  version and exit.

### Fixed

- **Publish workflow token permissions** -- Added explicit least-privilege
  `permissions: { contents: read }` on the integration gate job in
  `.github/workflows/publish.yml` to satisfy CodeQL
  `actions/missing-workflow-permissions`.

## [2.0.0rc2]

### Added

- **Vaultwarden Docker integration workflow** -- Added
  `.github/workflows/integration-docker.yml` to run end-to-end migration checks
  against a local Vaultwarden container in CI.
- **Vaultwarden e2e test** -- Added `tests/e2e_vaultwarden_test.py`, which
  creates a KeePass snapshot, runs `kp2bw`, and validates folder/item migration,
  URL + custom-field mapping, and idempotency.
- **Tracked integration fixtures** -- Added fixture allowlist rules in
  `tests/fixtures/.gitignore` plus seeded Vaultwarden fixture assets under
  `tests/fixtures/vaultwarden-data/` and `tests/fixtures/vaultwarden-certs/`.

### Changed

- **Contributor guidance** -- Updated `AGENTS.md` with release tag naming,
  Vaultwarden integration-test workflow details, and fixture tracking notes.
- **CLI interface modernization** -- Replaced legacy single-dash long options
  (`-kppw`, `-bworg`, etc.) with standard long flags plus short aliases
  (for example `--keepass-password` / `-k`) and added consistent `KP2BW_*`
  environment-variable support with clear precedence (`CLI > env > default`).

### Fixed

- **Sensitive logging** -- `BitwardenClient._exec()` no longer logs raw `bw`
  commands or raw command output; debug logs now use non-sensitive telemetry
  only (generic command message, exit code, output byte count).

## [2.0.0rc1] - 2026-02-23

### Added

- **Passkey migration** -- KeePassXC FIDO2/passkey credentials (`KPEX_PASSKEY_*`
  attributes) are detected and converted to Bitwarden `fido2Credentials` format
  (PEM private key → base64url, credential ID, relying party, user handle).
  Passkey attributes are excluded from regular custom fields to avoid
  duplication.
- **Recycle Bin filtering** -- deleted KeePass entries are now excluded by
  default; use `-include-recyclebin` to override.
- **Metadata migration** -- KeePass tags, expiry dates, and created/modified
  timestamps are stored as Bitwarden custom fields. Disable with `-no-metadata`.
- **Expired entry handling** -- expired entries are marked `[EXPIRED]` in notes;
  use `-skip-expired` to omit them entirely.
- Custom exception classes (`BitwardenClientError`, `ConversionError`) replacing
  bare `Exception` raises.
- Module-level loggers replacing root logger calls.
- New CLI flags: `-skip-expired`, `-include-recyclebin`, `-no-metadata`.
- Type annotations on all source modules (`bitwardenclient.py`, `cli.py`,
  `convert.py`). Type aliases for Bitwarden structures (`BwItem`, `EntryValue`,
  `AttachmentItem`, `Fido2Credentials`).
- **pykeepass type stubs** -- PEP 561 stub package (`packages/pykeepass-stubs/`)
  as a `uv` workspace member, covering `PyKeePass`, `Entry`, `Group`,
  `Attachment`, `BaseElement`, `icons`, and exception classes. Uses proper
  `lxml.etree.Element` / `ElementTree` types with `Literal`-based overloads on
  `_xpath()` for precise return-type narrowing. Enables full static type
  checking without upstream `py.typed` support.
- `py.typed` marker (PEP 561) for both `kp2bw` and stub packages.
- `__main__.py` module — enables `python -m kp2bw`.
- `__version__` exposed via `importlib.metadata` in `__init__.py`.
- **Publish workflow** -- Added `.github/workflows/publish.yml` release workflow
  with a version-check gate and dynamic PyPI environment URL.
- **Release smoke tests** -- Added `tests/smoke_test.py` and wired it into
  publish for both wheel and source distributions to verify package contents,
  entry points, imports, and CLI help.
- **Scripts workspace** -- Added `scripts/` JavaScript tooling (`package.json`,
  `tsconfig.json`, `bun.lock`, `.gitignore`) and typed `uv-version.mjs` helper
  for `actions/github-script`.
- **Stub publish workflow** -- Added `.github/workflows/publish-stubs.yml` with
  tag-based (`stubs-v*`) publishing for `pykeepass-stubs`, package-specific
  version checks, and explicit artifact publishing.
- **Stub release smoke tests** -- Added `tests/stubs_smoke_test.py` and wired it
  into stub-package publish checks for both wheel and source distributions.

### Changed (stubs)

- **baseelement.pyi** -- Replaced `_KeePassLike` protocol with direct
  `PyKeePass` import (circular imports are fine in `.pyi`). `_kp` attribute and
  `kp` parameter now typed `PyKeePass | None`. `icon` parameter drops `int`
  (only `str | None`). `icon` setter accepts `str | None`. `group` and
  `parentgroup` typed as `Group | None` (were `Any`). `parentgroup` declared as
  `@property` matching the actual `parentgroup = group` alias in source.
- **attachment.pyi** -- `_kp` now `PyKeePass | None`. `filename` getter returns
  `str | None` (lxml `.text` semantics). Added `__repr__`.
- **entry.pyi** -- `element` parameter accepts `ObjectifiedElement`. All
  string-field setters (`title`, `username`, `password`, `url`, `notes`, `otp`,
  `autotype_sequence`, `autotype_window`) accept `str | None`. Added `__str__`.
  `HistoryEntry` gains `__str__` and `__hash__`.
- **group.pyi** -- `element` parameter accepts `ObjectifiedElement`. `append`
  accepts `Entry | Group | list[Entry] | list[Group]`. Added `__str__`.
- **pykeepass.pyi** -- `add_entry` `tags` parameter accepts
  `list[str] | str | None`. Added `_encode_time` and `_decode_time`.
- **icons.pyi** -- New stub declaring `icons: SimpleNamespace`.
- **\_\_init\_\_.pyi** -- Added `icons` re-export and `__all__` entry.
- Ignored `PYI029` in stubs `ruff.lint` config (`__repr__` without `__eq__` is
  intentional — `__eq__` is on `BaseElement`).
- Marked stubs as partial in `py.typed` and expanded package
  metadata/classifiers in `packages/pykeepass-stubs/pyproject.toml`.
- Adopted independent stubs versioning (no lockstep with `pykeepass`) and
  declared supported runtime compatibility range `pykeepass>=4.1.1.post1,<4.2`.

### Changed

- Migrated project to `src/` layout with `uv` build system (was setuptools).
- Requires Python 3.14+.
- Rewrote README: mentions fork origin, tightened copy, added usage table.
- Removed legacy `setup.py`, `setup.cfg`, and `kp2bw.egg-info/`.
- Replaced `KpEntry`/`KpGroup` type aliases (were `Any`) with real pykeepass
  types (`Entry`, `Group`) from stubs, eliminating ~130 basedpyright warnings.
- Added contributor guidance to run `bun --cwd=scripts typecheck` when files
  under `scripts/` are changed.
- Updated local Zed JavaScript language-server configuration to include `tsgo`
  with `vtsls`.

### Fixed

- Type errors: `self._colls` could be `None` when accessed without guard.
- `except` clause used Python 2 syntax (`except A, B, C:` instead of
  `except (A, B, C):`).
- Tag-based import could add the same entry multiple times when it matched
  multiple tags (now breaks after first match).
- `entry.group` could be `None` — added guards for safe attribute access.
- Dead code: `group.path == "/"` comparisons (path is a list, never a string).
- Unnecessary `isinstance(self._import_tags, list)` check and dead else branch.
- Multiple ruff lint violations (35 total): import sorting, f-string
  conversions, redundant `.keys()`/`.items()` calls, nested `if` simplification,
  unused variables, overly broad exception catches, and more.

## [Upstream]

[`jampe/kp2bw@c9ef571eabd345db94751f7dec845e49756e9d47`](https://github.com/jampe/kp2bw/commit/c9ef571eabd345db94751f7dec845e49756e9d47)

[Unreleased]: https://github.com/kjanat/kp2bw/compare/v3.0.0a1...HEAD
[3.0.0a1]: https://github.com/kjanat/kp2bw/compare/v2.0.0...v3.0.0a1
[2.0.0]: https://github.com/kjanat/kp2bw/compare/v2.0.0rc3...v2.0.0
[2.0.0rc3]: https://github.com/kjanat/kp2bw/compare/v2.0.0rc2...v2.0.0rc3
[2.0.0rc2]: https://github.com/kjanat/kp2bw/compare/v2.0.0rc1...v2.0.0rc2
[2.0.0rc1]: https://github.com/kjanat/kp2bw/compare/c9ef571eabd345db94751f7dec845e49756e9d47...v2.0.0rc1
[Upstream]: https://github.com/kjanat/kp2bw/compare/jampe:kp2bw:f41b4e6a10a2c9fc55d144d048b4923c94eb43d6...kjanat:kp2bw:c9ef571eabd345db94751f7dec845e49756e9d47
