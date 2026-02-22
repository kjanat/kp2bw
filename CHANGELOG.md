# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
  `Attachment`, `BaseElement`, and exception classes. Uses proper
  `lxml.etree.Element` / `ElementTree` types with `Literal`-based overloads on
  `_xpath()` for precise return-type narrowing. Enables full static type
  checking without upstream `py.typed` support.

### Changed

- Migrated project to `src/` layout with `uv` build system (was setuptools).
- Requires Python 3.14+.
- Rewrote README: mentions fork origin, tightened copy, added usage table.
- Removed legacy `setup.py`, `setup.cfg`, and `kp2bw.egg-info/`.
- Replaced `KpEntry`/`KpGroup` type aliases (were `Any`) with real pykeepass
  types (`Entry`, `Group`) from stubs, eliminating ~130 basedpyright warnings.

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

## [1.1.0] - upstream

Last release from [jampe/kp2bw](https://github.com/jampe/kp2bw).

### Added

- Tag-based import filtering (`-import_tags`).
- Organization and collection support (`-bworg`, `-bwcoll`).
- Path-to-name prefixing (`-path2name`, `-path2nameskip`).
- Case-insensitive reference string handling.

### Fixed

- Misspelled method name in `_add_bw_entry_to_entries_dict`.
- Lowercase reference string resolution.

## [1.0.0] - upstream

### Added

- Initial KeePass 2.x to Bitwarden migration via `bw` CLI.
- Username/password REF field resolution.
- Custom property import (as text/hidden fields, >10k as attachments).
- Attachment import from KeePass.
- Long notes uploaded as `notes.txt` attachment.
- Idempotent import (skips existing entries).
- Nested folder recreation.
- TOTP/OTP field import.
- KeePass key file support.
- Verbose logging (`-v`).
- Cross-platform support (Windows, macOS, Linux).
- Full UTF-8 support.

[Unreleased]: https://github.com/kjanat/kp2bw/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/jampe/kp2bw/releases/tag/v1.1
[1.0.0]: https://github.com/jampe/kp2bw/commits/master
