# WORKFLOWS KNOWLEDGE BASE

## OVERVIEW

GitHub Actions workflows for release checks, publish orchestration, docker e2e, and PR helper comments.

## WHERE TO LOOK

| Task                            | Location                                   | Notes                                                    |
| ------------------------------- | ------------------------------------------ | -------------------------------------------------------- |
| Main package release flow       | `.github/workflows/publish.yml`            | Version tag push creates draft; public release is last   |
| Stubs release flow              | `.github/workflows/publish-stubs.yml`      | Triggered by `stubs-v*` tag pushes                       |
| Docker integration gate         | `.github/workflows/integration-docker.yml` | Reusable workflow; required before main publish          |
| Windows npm bw.cmd smoke        | `.github/workflows/windows-bw-cmd.yml`     | windows-latest; npm-installs bw and exercises the shim   |
| Codegen drift check             | `.github/workflows/codegen-check.yml`      | Fails when `bw_api_types.py` drifts from spec            |
| PR uvx helper comment lifecycle | `.github/actions/pr-test-comment/`         | Composite action; `pr-comment-bot.yml` calls it via `$/` |
| Version gate logic              | `.github/actions/version-check/`           | Produces `name`, `version`, `pypi_url` output contract   |

## CONVENTIONS

- Keep trigger split intact: main package on `v*` tags, stubs package on `stubs-v*` tags.
- Run check jobs through `$/.github/actions/version-check` with `package` and `tag-prefixes` inputs.
- Preserve workflow output keys from check jobs (`name`, `version`, `pypi_url`) and downstream references.
- Keep main publish gated by `integration-docker.yml` alongside artifact smoke tests and image validation.
- Integration runs the script regression adapters before the live matrix.
- Integration resolves the newest stable server and both CLI packages before testing. All CLI/test-group jobs must pass;
  the official CLI core job also compares golden snapshots. Core, attachment, format and scope groups each get
  a separate server and run in parallel; no group shares vault state. Tools come from `.tool-versions` through mise.
- Preserve smoke tests from built artifacts before `uv publish`.
- Stubs build/smoke validation runs without a deployment environment or OIDC write permission. The protected publish
  job is skipped for dry dispatches and consumes the exact validated artifact ID; main-package manual runs are always dry runs.

## ANTI-PATTERNS

- Changing release/tag trigger policy in workflows without matching `version-check` action updates.
- Renaming or removing check output keys without updating workflow expressions.
- Dropping docker integration dependency from main publish job.
- Skipping smoke tests from built wheel/sdist before publish.
- Logging command output that can expose credentials or session values.

## COMMANDS

```bash
# Validate script side of workflow contracts
bun run typecheck

# Run same docker e2e used by integration workflow
docker compose -f tests/docker-compose.yml build
docker compose -f tests/docker-compose.yml up --abort-on-container-exit --exit-code-from test
```

- `container.yml` tests both CLI variants of the production OCI image natively on amd64/arm64. Release calls consume the wheel artifact from
  the build job before any package publication; stubs do not call it. Publish only the tested image archives, with version-tag
  content-identity checks on retries. Stable releases update major/minor and CLI aliases after anonymous downloads succeed; unsuffixed tags select the `vw` variant.
  Background server/readiness steps use `wait` and `cancel`; PR validation has no package-write permission.

- `publish.yml` creates a draft first, attests wheel/sdist and image archives, and uploads them to the draft. Only the final job
  publishes the GitHub release. `scripts/release.py` and `scripts/release_images.py` implement immutable assets, registry checks
  and resume behavior. Manual dispatch never publishes. Release events never trigger another publication.
