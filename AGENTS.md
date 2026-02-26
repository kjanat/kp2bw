# PROJECT KNOWLEDGE BASE

Generated: 2026-02-26 Commit: `59ba3c2` Branch: `master`

## OVERVIEW

KeePass to Bitwarden migration CLI. Python runtime package + workspace stubs package.
Core flow migrates entries/folders/attachments/passkeys with `bw serve` as primary transport.

## STRUCTURE

```tree
kp2bw/
├── src/kp2bw/                   # Runtime package (CLI + conversion + bw transport + types)
│   └── AGENTS.md
├── specs/                       # OpenAPI spec for Bitwarden vault management API
│   └── vault-management-api.json
├── tests/                       # Script-style smoke + docker e2e + fixture contract
│   └── AGENTS.md
├── packages/pykeepass-stubs/    # Separate stubs release stream
│   └── AGENTS.md
├── scripts/                     # Release/version checks + codegen for github-script
│   └── AGENTS.md
└── .github/workflows/           # CI orchestration (release + integration + codegen drift)
    └── AGENTS.md
```

## WHERE TO LOOK

| Task                     | Location                              | Notes                                                              |
| ------------------------ | ------------------------------------- | ------------------------------------------------------------------ |
| CLI flags, prompts, envs | `src/kp2bw/cli.py`                    | Entrypoint `kp2bw.cli:main` and `python -m kp2bw` handoff          |
| Conversion orchestration | `src/kp2bw/convert.py`                | 3-phase top-level flow; item+attachment migration logic            |
| Bitwarden HTTP transport | `src/kp2bw/bw_serve.py`               | `bw serve` lifecycle, dedup index, batch create, attachment upload |
| Workflow policy details  | `.github/workflows/AGENTS.md`         | Trigger matrix, cross-workflow dependencies, output contracts      |
| Release version gating   | `scripts/version-check-shared.mjs`    | Normalizes release/tag prefixes; drives workflow gates             |
| Main package publishing  | `.github/workflows/publish.yml`       | Triggered by GitHub Release events, not tag push                   |
| Stubs publishing         | `.github/workflows/publish-stubs.yml` | Triggered by `stubs-v*` tags                                       |
| Codegen drift check      | `.github/workflows/codegen-check.yml` | Fails PRs when `_bw_api_types.py` drifts from spec                |
| Regenerate API types     | `scripts/generate-bw-types.sh`        | Run after editing `specs/vault-management-api.json`                |
| E2E migration behavior   | `tests/e2e_vaultwarden_test.py`       | Seeded Vaultwarden fixture + idempotency assertions                |

## CONVENTIONS

- Python baseline is `>=3.14` in root package; stubs package intentionally targets `>=3.11`.
- Ruff runs in preview mode, target `py314`; stubs package has separate Ruff/Pyright config.
- Intra-package imports are relative (`from .module import X`).
- `bw serve` is localhost-only and password is passed via env var, not CLI arg.
- Tests are executable scripts (`main()` + assertions), not pytest collection.
- `tests/test_script_adapters.py` provides pytest wrappers so `pytest` collects tests; script files remain the source-of-truth.
- Heavy adapters are opt-in: set `KP2BW_RUN_PACKAGING_TESTS=1` and/or `KP2BW_RUN_E2E_TESTS=1`.
- Workflow check jobs call `scripts/*.mjs` via `actions/github-script`; script output keys are workflow contracts.

## ANTI-PATTERNS (THIS PROJECT)

- Never use root logger calls (`logging.info(...)` etc.); use module logger.
- Never log raw `bw` command strings or raw command output.
- Never use bare `Exception`; use project exceptions (`BitwardenClientError`, `ConversionError`).
- Do not rewrite valid Python 3.14 comma-form `except X, Y:` syntax to tuple form.
- Do not assume publish-on-tag for main package; main publish is release-event driven.
- Do not change `scripts/version-check-shared.mjs` output shape (`name`, `version`, `pypi_url`) without workflow updates.

## UNIQUE STYLES

- Runtime and stubs are two packages with different release triggers and version rules.
- Release workflows smoke-test built artifacts (`uv run --isolated --no-project --with dist/...`).
- E2E fixture storage uses allowlist `.gitignore` to keep required DB/cert artifacts tracked.
- Dedup/idempotency is treated as an invariant (convert flow + e2e re-run assertion).
- Main publish `workflow_dispatch.dry` exists but does not currently gate publish step; stubs workflow does gate.

## COMMANDS

```bash
uv sync
uv run kp2bw <keepass_file>

uv run ruff check
uv run ty check
uv run basedpyright
uv run pytest -q tests/test_script_adapters.py

# Opt-in adapters for packaging and e2e scripts
KP2BW_RUN_PACKAGING_TESTS=1 uv run pytest -q tests/test_script_adapters.py -k "smoke or stubs"
KP2BW_RUN_E2E_TESTS=1 uv run pytest -q tests/test_script_adapters.py -k e2e

uv run python tests/e2e_vaultwarden_test.py

# When touching scripts/
bun --cwd=scripts typecheck

# Version bumping (multiple --bump flags allowed; order matters)
uv version --bump major --bump alpha [--dry-run]
uv version --bump stable [--dry-run]

# Stubs package variant
uv version --package pykeepass-stubs --bump major --bump alpha [--dry-run]
uv version --package pykeepass-stubs --bump stable [--dry-run]
```

## NOTES

- Keep docs scoped: child `AGENTS.md` files own implementation detail for their directory.
- Ignore transient dirs in analysis (`.venv/`, `.ruff_cache/`, `node_modules/`, `__pycache__/`).
- If changing release/version behavior, update both workflows and `scripts/*.mjs` together.
- For full `uv version` bump matrix/examples, use global skill `uv-versioning`.
- Keep domain detail in child AGENTS files (`src/kp2bw`, `tests`, `scripts`, `packages/pykeepass-stubs`, `.github/workflows`).
