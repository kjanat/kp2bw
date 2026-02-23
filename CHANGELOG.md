# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

[Unreleased]: https://github.com/kjanat/kp2bw/compare/v2.0.0rc3...HEAD
[2.0.0rc3]: https://github.com/kjanat/kp2bw/compare/v2.0.0rc2...v2.0.0rc3
[2.0.0rc2]: https://github.com/kjanat/kp2bw/compare/v2.0.0rc1...v2.0.0rc2
[2.0.0rc1]: https://github.com/kjanat/kp2bw/compare/c9ef571eabd345db94751f7dec845e49756e9d47...v2.0.0rc1
[Upstream]: https://github.com/kjanat/kp2bw/compare/jampe:kp2bw:f41b4e6a10a2c9fc55d144d048b4923c94eb43d6...kjanat:kp2bw:c9ef571eabd345db94751f7dec845e49756e9d47
