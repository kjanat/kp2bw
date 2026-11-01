# TESTS KNOWLEDGE BASE

## OVERVIEW

Tests are script-executable smoke/e2e checks, with dockerized Vaultwarden integration and tracked fixtures.

## WHERE TO LOOK

| Task                      | Location                            | Notes                                                    |
| ------------------------- | ----------------------------------- | -------------------------------------------------------- |
| bw command resolution     | `tests/bw_serve_command_test.py`    | Cross-platform argv wrapping + process teardown logic    |
| Manual-edit protection    | `tests/protect_edits_test.py`       | `KP2BW_SYNC` stamp, `is_user_modified`, protect vs force |
| Rate-limit retry          | `tests/bw_serve_rate_limit_test.py` | 429-in-400 detection, waits, retry budget (#65)          |
| Windows bw.cmd live smoke | `tests/windows_bw_cmd_smoke.py`     | Gated by `KP2BW_RUN_WIN_CMD_SMOKE=1`; Windows CI only    |
| Package smoke validation  | `tests/smoke_test.py`               | Verifies built artifact behavior, metadata, entry points |
| Stubs package validation  | `tests/stubs_smoke_test.py`         | Verifies `partial` marker + type-check consumption       |
| Full migration e2e        | `tests/e2e_vaultwarden_test.py`     | Rich seed + idempotency + golden snapshots               |
| Snapshot normalization    | `tests/snapshot.py`                 | Scrubs volatile fields, hashes attachments, golden diff  |
| Golden snapshots          | `tests/__snapshots__/*.json`        | Expected vault state for the official CLI                |
| Integration infra         | `tests/docker-compose.yml`          | Vaultwarden + test container orchestration               |
| Vaultwarden image seeding | `tests/Dockerfile.vaultwarden`      | Server image + DB/key fixtures                           |
| Test runner image         | `tests/Dockerfile.test`             | uv + bw CLI from bun.lock + test deps                    |
| Reusable bw setup         | `.github/actions/setup-bw`          | Installs a chosen `@bitwarden/cli` (matrix-able)         |
| Fixture retention rules   | `tests/fixtures/.gitignore`         | Allowlist keeps required DB/certs tracked                |

## CONVENTIONS

- `preview_test.py` verifies source/target reports, secret exclusion, source immutability and simulated writes.
  `e2e_preview_test.py` checks create/update/unchanged/protected predictions against actual migrations with both CLIs;
  a request guard rejects vault mutations during preview and inventory/revision comparisons confirm no changes.

- `history_test.py` covers historical password transitions and archive recovery, including saved/reopened KDBX files.
  `e2e_history_archive_test.py` verifies the opt-in archive through both CLIs, including filename collisions, binary
  recovery, replacement and unchanged reruns.

- No pytest collection model; scripts use `main()` and `AssertionError` checks.
- E2E command wrapper redacts sensitive args/output before logging.
- `e2e_support.py` logs in once per process with the CLI selected by `KP2BW_CLI` and opens one `bw serve` or
  `vw serve` client. Every read, write and in-process conversion (`Converter.convert(client)`) uses that client; a read
  after a write first syncs, because the official CLI can answer from its cache before a PUT lands there. CLI
  entrypoint runs and crash children get a private copy of the logged-in profile and session.
  Matrix lanes explicitly select their CLI so another installed binary cannot change the tested implementation.
- Integration expectations include idempotency (second run must not duplicate items).
- `bw_serve_exit_test.py` terminates a test process during a simulated request and verifies fatal batch abort,
  attachment-path propagation, and recovery from disconnects while the process remains alive.
- `e2e_vaultwarden_test.py [CHECK...]` runs the named checks in suite order over one client, or the whole suite without
  arguments. Goldens run first on a clean vault; the focused REF/TOTP/protected-field checks (`refs`) mutate it only
  afterwards.
- It also runs `e2e_metadata_test.py` with metadata explicitly enabled: persisted JSON tags/expiry, untouched YAML
  upgrades with and without sync stamps, protected metadata/notes edits, omitted empty metadata, and unchanged
  revisions on reruns. Synthetic items are cleaned up by both unique name and source UUID. The standalone script
  reuses `KP2BW_E2E_BW_PROFILE` after checking `BW_SERVER_URL` and `BW_TEST_EMAIL` against that saved profile.
- It then runs `e2e_scope_test.py`: `scope_fixture.py` creates an ephemeral organization via the disposable server's
  API, and the official CLI verifies fixed-collection import, URI reporting/migration, finalization, outside controls,
  and unchanged reruns. This fixture uses the test account's PBKDF2 configuration and keeps generated keys in memory.
- Reserved-field regressions cover protected/plain duplicates, escape-namespace collisions, historical imports,
  edit protection and finalization. `e2e_reserved_fields_test.py` checks preservation and unchanged reruns after goldens.
- `attachment_identity_test.py` checks collision allocation and legacy association. `e2e_attachment_identity_test.py`
  verifies distinct and identical same-named files, generated/original collisions, unchanged IDs and revisions,
  replacement of exactly one source, and retention when saving the association fails.

- `field_limits_test.py` checks UTF-8/AES-CBC field boundaries, final prefixes and preflight rejection,
  including separate REF items and recursive REF chains.
  `e2e_field_limits_test.py` verifies personal and organization round trips, attachment bytes and unchanged reruns.

- `e2e_passkey_test.py` checks native private-key round trips, hidden fallback fields and unchanged reruns after the
  golden comparisons, then removes its synthetic items.
- Fixtures are contract data; path and naming changes require docker + test updates together.
- Checkpoint tests cover atomic replacement, process locks, revision invalidation and preservation of remote edits.
  `e2e_checkpoint_test.py` kills migration processes before upload, after upload, after mapping and after deletion,
  then checks convergence and a rerun without attachment body transfers. With
  `KP2BW_E2E_VAULTWARDEN_CONTAINER`, it also removes a synthetic encrypted body from that disposable container to
  exercise recovery of an actual orphan slot. Each crash boundary is its own check (`crash_*`) on its own entry.
- The final live attachment batch regression verifies four distinct files on each of two items, unchanged reruns,
  replacement and a falsely acknowledged upload that must fail without deleting the old copy.
  `e2e_attachment_batch_test.py` can also run independently against an official Bitwarden test account using
  `BW_SERVER_URL`, `BW_TEST_EMAIL`, and `BW_TEST_PASSWORD`. `KP2BW_E2E_CLEANUP=1` removes only this run's synthetic
  items, identified by both random names and source UUIDs, including after a failed assertion.
  For Cloud, set `KP2BW_E2E_BW_PROFILE` to an already authenticated CLI profile to reuse its verified device instead
  of triggering email verification for a fresh profile. The regression checks the profile's server and account before
  creating fixtures; it leaves the profile available for later runs.

## GOLDEN SNAPSHOTS

- The e2e captures the migrated vault into a normalized, deterministic shape (`tests/snapshot.py`) and compares it
  against `tests/__snapshots__/`:
  - `vault_initial.json` -- after the first + idempotency passes.
  - `vault_after_update.json` -- after the update pass.
- Idempotency is proven at the snapshot level: pass 1 == pass 2 (and the refreshed state == its idempotent re-run),
  independent of the golden.
- Golden comparison is gated by `KP2BW_SNAPSHOT_GOLDEN=1` in the official CLI job.
- The golden depends on the CLI and
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
- `bw_serve_inventory_test.py` simulates empty, partial and stale-revision inventories after sync. It verifies recovery
  before dedup, bounded failure without a usable index, and revalidation after another sync.

## COMMANDS

```bash
uv run python tests/smoke_test.py
uv run python tests/stubs_smoke_test.py
uv run python tests/e2e_vaultwarden_test.py

docker compose -f tests/docker-compose.yml build
docker compose -f tests/docker-compose.yml up --abort-on-container-exit --exit-code-from test
```

- `templates_test.py` checks explicit template recognition, lossless field fallback, source KDBX loading and native-field
  signatures. `e2e_templates_test.py` runs native card/identity/secure-note creation, updates, unchanged reruns and manual
  edit protection with each CLI in the integration matrix.
- `e2e_ssh_test.py` checks native key creation, rotation, unchanged revisions, unsupported-source retention and manual
  edit protection with both CLIs. Its standalone entrypoint reuses a verified test profile. `ssh_mapping_test.py`
  verifies policy rejection precedes folder, collection and item operations.

- `item_selection_test.py` verifies selector identity, scope, REF dependencies and preflight rejection.
  `e2e_item_selection_test.py` checks selected creation, updates, forced overwrite, attachments and unchanged controls
  with both supported CLIs.

- `fixups_test.py` covers metadata schema validation, atomic per-item upgrades, sync stamps, races, personal/org/collection
  scope and CLI routing without KeePass. `e2e_fixups_test.py` verifies persisted JSON and URI values, protected controls,
  unchanged reruns and the URI-only command with both CLIs.

- `container_image_test.py` runs the production image against a disposable server using a fresh named state volume.
  It verifies non-root execution, read-only database/keyfile input, login persistence across containers, attachment bytes,
  unchanged reruns and SIGTERM teardown. The container workflow runs both CLI variants natively on both supported
  architectures.

- CI assigns the checks to shard jobs per CLI by their measured CI duration (heaviest first, least-loaded worker
  slot). Each job runs its worker slots as a `parallel:` step group; every slot starts its own disposable server from
  the same image, with `BW_SERVER_URL` and `KP2BW_E2E_VAULTWARDEN_CONTAINER` set to that server. Update the weights in
  `integration-docker.yml` when a check is added or its duration changes. Sequences that need two CLI runs or several
  slow passes are split into checks with their own fixtures, each starting from a freshly converged entry.
- Every CLI flag and environment combination that the e2e scripts exercise keeps at least one `uv run kp2bw` run with
  its exit code asserted; repeated runs of the same combination run in process through `Converter.convert(client)`.

- `npx_bootstrap_test.py` uses the real npm registry without vault access: a hostile project supplies local launchers,
  package metadata, `.npmrc` and injected environment settings. CI checks official-registry bootstrap and offline CLI
  execution on Linux and Windows. The pytest adapter is gated by `KP2BW_RUN_NPX_TESTS=1`.
