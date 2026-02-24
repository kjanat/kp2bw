# WORKFLOWS KNOWLEDGE BASE

## OVERVIEW

GitHub Actions workflows for release checks, publish orchestration, docker e2e, and PR helper comments.

## WHERE TO LOOK

| Task                            | Location                                   | Notes                                                  |
| ------------------------------- | ------------------------------------------ | ------------------------------------------------------ |
| Main package release flow       | `.github/workflows/publish.yml`            | Triggered by GitHub Release events, not tag push       |
| Stubs release flow              | `.github/workflows/publish-stubs.yml`      | Triggered by `stubs-v*` tag pushes                     |
| Docker integration gate         | `.github/workflows/integration-docker.yml` | Reusable workflow; required before main publish        |
| PR uvx helper comment lifecycle | `.github/workflows/pr-comment-bot.yml`     | Creates/updates archived test command comment          |
| Version gate logic              | `scripts/version-check-shared.mjs`         | Produces `name`, `version`, `pypi_url` output contract |

## CONVENTIONS

- Keep trigger split intact: main package on release events, stubs package on `stubs-v*` tags.
- Run check jobs through `actions/github-script` importing `scripts/uv-version.mjs` or `scripts/stubs-version.mjs`.
- Preserve workflow output keys from check jobs (`name`, `version`, `pypi_url`) and downstream references.
- Keep main publish gated by `integration-docker.yml` (`needs: [check, integration]`).
- Preserve smoke tests from built artifacts before `uv publish`.
- Keep stubs `dry` guard behavior in publish step; root workflow `dry` is currently informational.

## ANTI-PATTERNS

- Changing release/tag trigger policy in workflows without matching `scripts/*.mjs` updates.
- Renaming or removing check output keys without updating workflow expressions.
- Dropping docker integration dependency from main publish job.
- Skipping smoke tests from built wheel/sdist before publish.
- Logging command output that can expose credentials or session values.

## COMMANDS

```bash
# Validate script side of workflow contracts
bun --cwd=scripts typecheck

# Run same docker e2e used by integration workflow
docker compose -f tests/docker-compose.yml build
docker compose -f tests/docker-compose.yml up --abort-on-container-exit --exit-code-from test
```
