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

CI tests the newest stable releases of `@bitwarden/cli` and `@kjanat/vaultwarden-cli` against the newest stable
Vaultwarden server. Both jobs must pass. The run summary records exact versions and the server image digest.

The official CLI job also compares golden snapshots. `tests/vw_bw_adapter.sh` maps the existing `bw` test commands and
profile/session variables to `vw`, exercising the published CLI and its `@kjanat/vaultwarden` SDK.

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
validated image archives. Main releases pass the tested release wheel to this workflow after PyPI publishing succeeds.
Publishing loads those archives without rebuilding, refuses an existing version tag, and updates `latest` only for
stable releases. Stubs releases do not invoke it. Run `tests/container_image_test.py` against a disposable fixture with
`KP2BW_CONTAINER_IMAGE`, `KP2BW_CONTAINER_VERSION`, `KP2BW_CONTAINER_BW_VERSION` and `BW_SERVER_URL` set.
