<!--markdownlint-disable-file no-duplicate-heading-->

# Changelog -- pykeepass-stubs

All notable changes to the `pykeepass-stubs` package are documented here. This package has its own version stream,
independent of `kp2bw` and `pykeepass`.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.2] - 2026-06-08

### Added

- **MIT license** -- the stubs are original work (not derived from the unlicensed `kp2bw` fork base), so they are now
  MIT-licensed: a `LICENSE` file plus a PEP 639 `license = "MIT"` expression and `license-files`.

### Changed

- Packaging metadata polish: added `keywords`, the `Operating System :: OS Independent` classifier, and a `Homepage`
  URL.

## [0.1.1] - 2026-06-08

### Fixed

- Added an explicit `lxml>=6.0.2` runtime dependency so a standalone install of the stubs resolves the runtime `lxml`
  import; previously only `types-lxml` was declared, leaving the runtime `lxml` import unsatisfied.

## [0.1.0] - 2026-02-23

### Added

- Initial PEP 561 stub package for `pykeepass`, covering `PyKeePass`, `Entry`, `Group`, `Attachment`, `BaseElement`,
  `icons`, and the exception classes, with proper `lxml.etree` types and `Literal`-based `_xpath()` overloads for
  precise return-type narrowing. Marked partial via `py.typed`; versioned independently of `pykeepass` and `kp2bw`.

[Unreleased]: https://github.com/kjanat/kp2bw/compare/stubs-v0.1.2...HEAD
[0.1.2]: https://github.com/kjanat/kp2bw/compare/stubs-v0.1.1...stubs-v0.1.2
[0.1.1]: https://github.com/kjanat/kp2bw/compare/stubs-v0.1.0...stubs-v0.1.1
[0.1.0]: https://github.com/kjanat/kp2bw/tree/stubs-v0.1.0
