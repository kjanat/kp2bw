# TESTS KNOWLEDGE BASE

## OVERVIEW

Tests are script-executable smoke/e2e checks, with dockerized Vaultwarden integration and tracked fixtures.

## WHERE TO LOOK

| Task                      | Location                            | Notes                                                     |
| ------------------------- | ----------------------------------- | --------------------------------------------------------- |
| bw command resolution     | `tests/bw_serve_command_test.py`    | Cross-platform argv wrapping + process teardown logic     |
| Manual-edit protection    | `tests/protect_edits_test.py`       | `KP2BW_SYNC` stamp, `_is_user_modified`, protect vs force |
| Rate-limit retry          | `tests/bw_serve_rate_limit_test.py` | 429-in-400 detection, waits, retry budget (#65)           |
| Windows bw.cmd live smoke | `tests/windows_bw_cmd_smoke.py`     | Gated by `KP2BW_RUN_WIN_CMD_SMOKE=1`; Windows CI only     |
| Package smoke validation  | `tests/smoke_test.py`               | Verifies built artifact behavior, metadata, entry points  |
| Stubs package validation  | `tests/stubs_smoke_test.py`         | Verifies `partial` marker + type-check consumption        |
| Full migration e2e        | `tests/e2e_vaultwarden_test.py`     | Rich seed + idempotency + golden snapshots                |
| Snapshot normalization    | `tests/_snapshot.py`                | Scrubs volatile fields, hashes attachments, golden diff   |
| Golden snapshots          | `tests/__snapshots__/*.json`        | Committed expected vault state (pinned bw owns them)      |
| Integration infra         | `tests/docker-compose.yml`          | Vaultwarden + test container orchestration                |
| Vaultwarden image seeding | `tests/Dockerfile.vaultwarden`      | Pinned image + DB/key fixtures                            |
| Test runner image         | `tests/Dockerfile.test`             | uv + lockfile-pinned bw CLI + test deps                   |
| Reusable bw setup         | `.github/actions/setup-bw`          | Installs a chosen `@bitwarden/cli` (matrix-able)          |
| Fixture retention rules   | `tests/fixtures/.gitignore`         | Allowlist keeps required DB/certs tracked                 |

## CONVENTIONS

- No pytest collection model; scripts use `main()` and `AssertionError` checks.
- E2E command wrapper redacts sensitive args/output before logging.
- Integration expectations include idempotency (second run must not duplicate items).
- The Vaultwarden E2E runs focused REF/TOTP/protected-field checks after golden snapshots, so those checks can mutate
  the vault without changing the comprehensive golden fixtures.
- It then runs `e2e_scope_test.py`: `_scope_fixture.py` creates an ephemeral organization via the disposable server's
  API, and the official CLI verifies fixed-collection import, URI reporting/migration, finalization, outside controls,
  and unchanged reruns. This fixture uses the test account's PBKDF2 configuration and keeps generated keys in memory.
- Fixtures are contract data; path and naming changes require docker + test updates together.
- The final live attachment batch regression verifies four distinct files on each of two items, unchanged reruns,
  replacement and a falsely acknowledged upload that must fail without deleting the old copy.
  `e2e_attachment_batch_test.py` can also run independently against an official Bitwarden test account using
  `BW_SERVER_URL`, `BW_TEST_EMAIL`, and `BW_TEST_PASSWORD`. `KP2BW_E2E_CLEANUP=1` removes only this run's synthetic
  items, identified by both random names and source UUIDs, including after a failed assertion.
  For Cloud, set `KP2BW_E2E_BW_PROFILE` to an already authenticated CLI profile to reuse its verified device instead
  of triggering email verification for a fresh profile. The regression checks the profile's server and account before
  creating fixtures; it leaves the profile available for later runs.

## GOLDEN SNAPSHOTS

- The e2e captures the migrated vault into a normalized, deterministic shape (`tests/_snapshot.py`) and compares it
  against `tests/__snapshots__/`:
  - `vault_initial.json` -- after the first + idempotency passes.
  - `vault_after_update.json` -- after the update pass.
- Idempotency is proven at the snapshot level: pass 1 == pass 2 (and the refreshed state == its idempotent re-run),
  independent of the golden.
- Golden compare is gated by `KP2BW_SNAPSHOT_GOLDEN=1`; the **pinned**-CLI matrix leg owns it, the `latest` canary leg
  runs behavioral checks only.
- The golden is a function of the exact `@bitwarden/cli` (root `package.json` + `bun.lock`) **and** the pinned
  Vaultwarden image (`tests/Dockerfile.vaultwarden`). When Dependabot bumps either, regenerate and review the diff:

  ```bash
  KP2BW_UPDATE_SNAPSHOTS=1 docker compose -f tests/docker-compose.yml up \
    --abort-on-container-exit --exit-code-from test
  ```

  The bind mount in `docker-compose.yml` writes the regenerated goldens back into the working tree.

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
