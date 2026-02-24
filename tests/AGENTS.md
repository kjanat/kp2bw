# TESTS KNOWLEDGE BASE

## OVERVIEW

Tests are script-executable smoke/e2e checks, with dockerized Vaultwarden integration and tracked fixtures.

## WHERE TO LOOK

| Task                      | Location                        | Notes                                                    |
| ------------------------- | ------------------------------- | -------------------------------------------------------- |
| Package smoke validation  | `tests/smoke_test.py`           | Verifies built artifact behavior, metadata, entry points |
| Stubs package validation  | `tests/stubs_smoke_test.py`     | Verifies `partial` marker + type-check consumption       |
| Full migration e2e        | `tests/e2e_vaultwarden_test.py` | Runs conversion twice and asserts idempotency            |
| Integration infra         | `tests/docker-compose.yml`      | Vaultwarden + test container orchestration               |
| Vaultwarden image seeding | `tests/Dockerfile.vaultwarden`  | Loads DB/key fixtures into image                         |
| Test runner image         | `tests/Dockerfile.test`         | Installs uv + bw CLI + test deps                         |
| Fixture retention rules   | `tests/fixtures/.gitignore`     | Allowlist keeps required DB/certs tracked                |

## CONVENTIONS

- No pytest collection model; scripts use `main()` and `AssertionError` checks.
- E2E command wrapper redacts sensitive args/output before logging.
- Integration expectations include idempotency (second run must not duplicate items).
- Fixtures are contract data; path and naming changes require docker + test updates together.

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
