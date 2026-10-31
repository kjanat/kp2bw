# Contributing

## Development tools

Project tools are managed by mise through `.tool-versions`:

```sh
mise install
uv sync --frozen
bun install --frozen-lockfile
```

The standalone basedpyright tool uses mise's `npm:basedpyright` backend. The package scripts continue to run Python
checks through `uv run`, using the project's locked dependencies. Run `dprint fmt` for formatting, including TOML.

## Compatibility tests

CI tests the newest stable releases of [`@bitwarden/cli`][npm:bw] and [`@kjanat/vaultwarden-cli`][npm:vw] against the
newest stable Vaultwarden server. All test groups for both CLIs must pass. The run summary records exact versions and
the server image digest.

The official CLI job also compares golden snapshots. The Vaultwarden CLI job runs the same checks with `vw`, exercising
the published CLI and its [`@kjanat/vaultwarden`][npm:vw-sdk] SDK.

[npm:bw]: @bitwarden/cli
[npm:vw]: @kjanat/vaultwarden-cli
[npm:vw-sdk]: @kjanat/vaultwarden

## Container development

Build the wheel first, then build the production image. The Dockerfile accepts only the selected wheel from the build
context; test fixtures, credentials, CLI profiles and repository development dependencies are excluded.

```bash
uv build --no-sources --wheel
CLI_PACKAGE=@kjanat/vaultwarden-cli # Or @bitwarden/cli
CLI_VERSION="$(npm view "$CLI_PACKAGE" version)"
docker build --build-arg KP2BW_VERSION="$(uv version --short)" \
  --build-arg CLI_PACKAGE="$CLI_PACKAGE" --build-arg CLI_VERSION="$CLI_VERSION" \
  --build-arg REVISION="$(git rev-parse HEAD)" --tag kp2bw-local .
```

`container.yml` resolves exact CLI/base-image versions, builds and tests natively on both architectures, and saves the
validated image archives. Main releases build these images from the same wheel that will be published to PyPI.
Publishing loads those archives without rebuilding, rejects conflicting version tags, and updates `latest` only after
public availability checks for stable releases. Stubs releases do not invoke it. Run `tests/container_image_test.py`
against a disposable fixture with `KP2BW_CONTAINER_IMAGE`, `KP2BW_CONTAINER_VERSION`, `KP2BW_CONTAINER_BW_VERSION` and
`BW_SERVER_URL` set.

## Releasing kp2bw

Merge the version bump, lockfile, dated changelog section and any release notes first. Push a tag pointing to that exact
commit to start publication:

```sh
git tag -a vX.Y.Z -m "kp2bw X.Y.Z"
git push origin vX.Y.Z
```

The `Publish` workflow verifies that the tag matches the package version, then creates a **draft** GitHub release. Notes
come from `.github/release-notes/vX.Y.Z.md` when provided; otherwise the versioned changelog, existing PyPI badge and
GitHub PR/compare links form the initial draft. You can edit its text while the pipeline runs; retries and finalization
do not replace those edits. It builds the wheel (`.whl`) and source distribution (`.tar.gz`), attests them, and attaches
both files, the provenance bundle and SHA-256 manifest to the draft. Container builds use that same wheel. Both CLI
variants are tested natively on amd64 and arm64; their archives, provenance bundles and checksum manifest are also
attached to the draft.

Package smoke tests and the full integration matrix must pass before any distribution is published. PyPI publication
uses trusted publishing; GHCR receives the tested images without rebuilding. Public downloads from PyPI must match the
built files, and anonymous pulls of both image variants and architectures must succeed. Only then are stable aliases
updated and the GitHub draft made public. Prereleases do not update `latest` or the stable aliases.

A private GHCR package cannot pass anonymous verification: ensure the package visibility allows public pulls. Publishing
on PyPI and GHCR is not atomic; partial uploads can exist while the GitHub release remains a draft. Use **Re-run failed
jobs** on the original workflow run to resume with its retained artifacts. Existing files or version tags are reused
only when their content matches. Do not move the tag, replace assets, or start a different run for that version; a
changed build requires a new version. Workflow artifacts are retained for 90 days, and the draft assets remain available
for inspection. The draft records the source commit and originating run.

To validate the build/test pipeline without creating a draft, tag, attestation or registry upload, dispatch `Publish`
manually on the desired ref with its matching version. Manual runs are always dry runs. Do not create a public GitHub
release to trigger publication: release events no longer start the workflow. The separately versioned stubs package
continues to use its `stubs-v*` tag workflow.
