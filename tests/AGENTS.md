# TESTS KNOWLEDGE BASE

## OVERVIEW

Tests are script-executable smoke/e2e checks, with dockerized Vaultwarden integration and tracked fixtures.

## WHERE TO LOOK

| Task                      | Location                         | Notes                                                    |
| ------------------------- | -------------------------------- | -------------------------------------------------------- |
| bw command resolution     | `tests/bw_serve_command_test.py` | Cross-platform argv wrapping + process teardown logic    |
| Windows bw.cmd live smoke | `tests/windows_bw_cmd_smoke.py`  | Gated by `KP2BW_RUN_WIN_CMD_SMOKE=1`; Windows CI only    |
| Package smoke validation  | `tests/smoke_test.py`            | Verifies built artifact behavior, metadata, entry points |
| Stubs package validation  | `tests/stubs_smoke_test.py`      | Verifies `partial` marker + type-check consumption       |
| Full migration e2e        | `tests/e2e_vaultwarden_test.py`  | Rich seed + idempotency + golden snapshots               |
| Snapshot normalization    | `tests/_snapshot.py`             | Scrubs volatile fields, hashes attachments, golden diff  |
| Golden snapshots          | `tests/__snapshots__/*.json`     | Committed expected vault state (pinned bw owns them)     |
| Integration infra         | `tests/docker-compose.yml`       | Vaultwarden + test container orchestration               |
| Vaultwarden image seeding | `tests/Dockerfile.vaultwarden`   | Pinned image + DB/key fixtures                           |
| Test runner image         | `tests/Dockerfile.test`          | uv + lockfile-pinned bw CLI + test deps                  |
| Reusable bw setup         | `.github/actions/setup-bw`       | Installs a chosen `@bitwarden/cli` (matrix-able)         |
| Fixture retention rules   | `tests/fixtures/.gitignore`      | Allowlist keeps required DB/certs tracked                |

## CONVENTIONS

- No pytest collection model; scripts use `main()` and `AssertionError` checks.
- E2E command wrapper redacts sensitive args/output before logging.
- Integration expectations include idempotency (second run must not duplicate items).
- Fixtures are contract data; path and naming changes require docker + test updates together.

## GOLDEN SNAPSHOTS

- The e2e captures the migrated vault into a normalized, deterministic shape
  (`tests/_snapshot.py`) and compares it against `tests/__snapshots__/`:
  - `vault_initial.json` -- after the first + idempotency passes.
  - `vault_after_update.json` -- after the update pass.
- Idempotency is proven at the snapshot level: pass 1 == pass 2 (and the
  refreshed state == its idempotent re-run), independent of the golden.
- Golden compare is gated by `KP2BW_SNAPSHOT_GOLDEN=1`; the **pinned**-CLI matrix
  leg owns it, the `latest` canary leg runs behavioral checks only.
- The golden is a function of the exact `@bitwarden/cli` (root `package.json` +
  `bun.lock`) **and** the pinned Vaultwarden image (`tests/Dockerfile.vaultwarden`).
  When Dependabot bumps either, regenerate and review the diff:

  ```bash
  KP2BW_UPDATE_SNAPSHOTS=1 docker compose -f tests/docker-compose.yml up \
    --abort-on-container-exit --exit-code-from test
  ```

  The bind mount in `docker-compose.yml` writes the regenerated goldens back
  into the working tree.

## ANTI-PATTERNS

- Converting tests to framework-only style without preserving direct script execution.
- Printing raw secrets/session data in helper command output.
- Editing fixture content ad hoc without updating assertions and compose setup.
- Treating e2e rerun duplicates as acceptable behavior.

## COMMANDS

```bash
uv run python tests/smoke_test.py
uv run python tests/stubs_smoke_test.py
uv run python tests/e2e_vaultwarden_test.py

docker compose -f tests/docker-compose.yml build
docker compose -f tests/docker-compose.yml up --abort-on-container-exit --exit-code-from test
```
