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
  `Attachment`, `BaseElement`, `icons`, and exception classes. Uses proper
  `lxml.etree.Element` / `ElementTree` types with `Literal`-based overloads on
  `_xpath()` for precise return-type narrowing. Enables full static type
  checking without upstream `py.typed` support.
- `py.typed` marker (PEP 561) for both `kp2bw` and stub packages.
- `__main__.py` module — enables `python -m kp2bw`.
- `__version__` exposed via `importlib.metadata` in `__init__.py`.

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

## [Upstream]

jampe/kp2bw@c9ef571eabd345db94751f7dec845e49756e9d47

[Unreleased]: https://github.com/kjanat/kp2bw/compare/jampe:kp2bw:c9ef571eabd345db94751f7dec845e49756e9d47...HEAD
[Upstream]: https://github.com/kjanat/kp2bw/compare/jampe:kp2bw:f41b4e6a10a2c9fc55d144d048b4923c94eb43d6...kjanat:kp2bw:c9ef571eabd345db94751f7dec845e49756e9d47
