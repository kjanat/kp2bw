# SCRIPTS KNOWLEDGE BASE

## OVERVIEW

JavaScript helper modules for release-time version checks inside `actions/github-script` workflows.

## WHERE TO LOOK

| Task                  | Location                         | Notes                                           |
| --------------------- | -------------------------------- | ----------------------------------------------- |
| Release version check | `.github/actions/version-check/` | Composite action; both publish workflows use it |
| Regenerate API types  | `scripts/generate-bw-types.sh`   | Codegen from `specs/vault-management-api.json`  |
| Tooling config        | `package.json`                   | Root Bun tooling for typecheck-only workflow    |
| Typecheck config      | `tsconfig.json`                  | JS-check setup for github-script modules        |

## CONVENTIONS

- Treat scripts as workflow runtime code, not build artifacts.
- Keep script outputs stable: return version/name/url fields consumed by workflows.
- Update scripts and workflow triggers together when tag/release policy changes.
- Use Bun only for local typechecking; CI runtime executes under `actions/github-script`.

## ANTI-PATTERNS

- Changing release tag normalization in one script only.
- Adding Node/Bun runtime assumptions not available in `github-script` context.
- Relying on local-only type behavior without running `bun run typecheck`.

## COMMANDS

```bash
bun install
bun run typecheck
```
