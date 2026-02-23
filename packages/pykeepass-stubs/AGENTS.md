# STUBS PACKAGE KNOWLEDGE BASE

## OVERVIEW

Separate PEP 561 stubs distribution for `pykeepass`; independent version stream and publish trigger.

## STRUCTURE

```tree
packages/pykeepass-stubs/
├── pyproject.toml                # Stubs package metadata + tool config
├── README.md                     # Compatibility and release notes for stubs users
└── src/pykeepass-stubs/
    ├── *.pyi                     # Type surface for pykeepass modules
    └── py.typed                  # Contains `partial`
```

## WHERE TO LOOK

| Task                         | Location                                             | Notes                                          |
| ---------------------------- | ---------------------------------------------------- | ---------------------------------------------- |
| Bump stubs version           | `packages/pykeepass-stubs/pyproject.toml`            | Must align with `stubs-v*` release tag         |
| Add/change stub types        | `packages/pykeepass-stubs/src/pykeepass-stubs/*.pyi` | Keep signatures aligned with upstream behavior |
| Stub packaging behavior      | `packages/pykeepass-stubs/pyproject.toml`            | `Typing :: Stubs Only`, include `py.typed`     |
| Validate checker consumption | `tests/stubs_smoke_test.py`                          | Enforces marker and typed diagnostics          |

## CONVENTIONS

- Python baseline here is `>=3.11` (different from runtime package `>=3.14`).
- Ruff/Pyright configs are local to this package; keep root/runtime and stubs settings separate.
- `py.typed` must remain `partial` for partial-stub semantics.
- Keep this package type-only; no runtime module logic.

## ANTI-PATTERNS

- Releasing stubs using main package release workflow.
- Dropping `partial` marker or moving `py.typed` outside shipped package path.
- Letting `.pyi` signatures drift from real `pykeepass` behavior.
- Mixing runtime dependency changes into stubs-only releases without need.

## COMMANDS

```bash
uv build --package pykeepass-stubs --no-sources --out-dir dist-stubs
uv run python tests/stubs_smoke_test.py

# Version bumping (multiple --bump flags allowed; order matters)
# Example: 2.0.0 -> 3.0.0a1
uv version --package pykeepass-stubs --bump major --bump alpha [--dry-run]

# Example: 3.0.0a1 -> 3.0.0
uv version --package pykeepass-stubs --bump stable [--dry-run]

# Full bump matrix/examples: global skill `uv-versioning`
```
