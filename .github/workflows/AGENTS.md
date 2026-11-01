# WORKFLOWS KNOWLEDGE BASE

## OVERVIEW

GitHub Actions workflows for release checks, publish orchestration, docker e2e, and PR helper comments.

## WHERE TO LOOK

| Task                            | Location                                                    | Notes                                                       |
| ------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------- |
| Main package release flow       | `.github/workflows/publish.yml`                             | Version tag push creates draft; public release is last      |
| Stubs release flow              | `.github/workflows/publish-stubs.yml`                       | Triggered by `stubs-v*` tag pushes                          |
| Docker integration gate         | `.github/workflows/integration-docker.yml`                  | Reusable; `lane` input selects `bitwarden`/`vaultwarden`    |
| Per-CLI compatibility runs      | `.github/workflows/integration-{vaultwarden,bitwarden}.yml` | PR/master callers; badges; `vaultwarden / gate` is required |
| Windows npm bw.cmd smoke        | `.github/workflows/windows-bw-cmd.yml`                      | windows-latest; npm/bun-installed bw and vw launcher checks |
| Codegen drift check             | `.github/workflows/codegen-check.yml`                       | Fails when `bw_api_types.py` drifts from spec               |
| PR uvx helper comment lifecycle | `.github/actions/pr-test-comment/`                          | Composite action; `pr-comment-bot.yml` calls it via `$/`    |
| Version gate logic              | `.github/actions/version-check/`                            | Produces `name`, `version`, `pypi_url` output contract      |

## CONVENTIONS

- Keep trigger split intact: main package on `v*` tags, stubs package on `stubs-v*` tags.
- Run check jobs through `$/.github/actions/version-check` with `package` and `tag-prefixes` inputs.
- Preserve workflow output keys from check jobs (`name`, `version`, `pypi_url`) and downstream references.
- Keep main publish gated by the `vaultwarden` lane of `integration-docker.yml` alongside artifact smoke tests and
  image validation. The `bitwarden` lane runs in every release but never blocks it.
- Integration runs the script regression adapters before the live matrix.
- Integration resolves the newest stable server and both CLI packages before testing. Each CLI runs every check,
  golden snapshots included, in its own lane behind its own gate job; only the `vaultwarden` gate is required.
  Every worker slot gets a separate server; no slot shares vault state. Tools come from `.tool-versions` through mise.
- Preserve smoke tests from built artifacts before `uv publish`.
- Stubs build/smoke validation runs without a deployment environment or OIDC write permission. The protected publish
  job is skipped for dry dispatches and consumes the exact validated artifact ID; main-package manual runs are always dry runs.

## ANTI-PATTERNS

- Changing release/tag trigger policy in workflows without matching `version-check` action updates.
- Renaming or removing check output keys without updating workflow expressions.
- Dropping the `vaultwarden` integration dependency from the main publish job.
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
  Each CLI has its own validation job and gate (`container-vw`, `container-bw`); only `container-vw` is a required check.
  The `changes` filter runs on pull requests only. Validation jobs run whenever `prepare` succeeded, and each gate
  requires its validation result to equal the `prepare` result.
  A release calls `container.yml` once per CLI and waits for the vw images only. Without tested bw archives for both
  architectures, `release-images.sh` publishes and promotes the vw images alone.

- `publish.yml` creates a draft first, attests wheel/sdist and image archives, and uploads them to the draft. Only the final job
  publishes the GitHub release. `scripts/release.sh` and `scripts/release-images.sh` implement immutable assets, registry checks
  and resume behavior. Manual dispatch never publishes. Release events never trigger another publication.
