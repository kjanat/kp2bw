# SCRIPTS KNOWLEDGE BASE

## OVERVIEW

JavaScript helper modules for release-time version checks inside `actions/github-script` workflows.

## WHERE TO LOOK

| Task                              | Location                           | Notes                                       |
| --------------------------------- | ---------------------------------- | ------------------------------------------- |
| Shared version parsing/validation | `scripts/version-check-shared.mjs` | Prefix normalization + mismatch errors      |
| Main package release check        | `scripts/uv-version.mjs`           | Accepts `v`-prefixed release tags           |
| Stubs package release check       | `scripts/stubs-version.mjs`        | Accepts `stubs-v` and `v` prefixes          |
| Tooling config                    | `scripts/package.json`             | `tsgo --noEmit` for typecheck-only workflow |
| Typecheck config                  | `scripts/tsconfig.json`            | JS-check setup for github-script modules    |

## CONVENTIONS

- Treat scripts as workflow runtime code, not build artifacts.
- Keep script outputs stable: return version/name/url fields consumed by workflows.
- Update scripts and workflow triggers together when tag/release policy changes.
- Use Bun only for local typechecking; CI runtime executes under `actions/github-script`.

## ANTI-PATTERNS

- Changing release tag normalization in one script only.
- Adding Node/Bun runtime assumptions not available in `github-script` context.
- Relying on local-only type behavior without running `bun --cwd=scripts typecheck`.

## COMMANDS

```bash
bun --cwd=scripts install
bun --cwd=scripts typecheck
```
