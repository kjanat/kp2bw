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
