# KP2BW - KeePass to Bitwarden Converter

<a href="https://pypi.org/project/kp2bw/">
  <img src="https://img.shields.io/pypi/v/kp2bw?logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMS42OTYgMzAuMDI0Ij48ZyBzdHJva2U9IiNjY2MiIHN0cm9rZS1saW5lam9pbj0iYmV2ZWwiIHN0cm9rZS13aWR0aD0iLjM1NSI%2BPHBhdGggZmlsbD0iI2Y3ZjdmNCIgZD0ibS4xNzggNS45MTIgMTUuNTU1IDUuNjYyTDMxLjUxOSA1LjgzIDE1Ljk2My4xNjd6Ii8%2BPHBhdGggZmlsbD0iI2ZmZiIgZD0iTTE1LjczMyAxMS41NzR2MTguMjgzbDE1Ljc4Ni01Ljc0NlY1LjgzeiIvPjxwYXRoIGZpbGw9IiNlZmVlZWEiIGQ9Im0uMTc4IDUuOTEyIDE1LjU1NSA1LjY2MnYxOC4yODNMLjE3OCAyNC4xOTV6Ii8%2BPC9nPjwvc3ZnPg%3D%3D&color=3775A9" alt="PyPI">
</a>

Migrates KeePass databases to Bitwarden via the `bw` CLI,\
with advantages over the built-in Bitwarden importer:

- <details><summary><b>Encrypted in-memory transfer</b></summary> Data never hits disk unencrypted (except attachments, which are cleaned up after upload).</details>
- <details><summary><b>KeePass REF resolution</b></summary> Username/password references are resolved.<br> Matching credentials merge URLs into one entry; differing ones create new entries.</details>
- <details open><summary><b>Passkey migration</b></summary> KeePassXC FIDO2/passkey credentials (<code>KPEX_PASSKEY_*</code>) are converted to Bitwarden <code>fido2Credentials</code>.</details>
- <details><summary><b>Custom properties &amp; attachments</b></summary> Imported as Bitwarden custom fields or attachments (values &gt;10k chars auto-upload as files).</details>
- <details><summary><b>Long notes handling</b></summary> Notes exceeding 10k chars are uploaded as <code>notes.txt</code> attachments.</details>
- <details><summary><b>Idempotent re-runs that sync changes</b></summary> Safe to run repeatedly; existing entries are updated in place when their KeePass content changed (notes, credentials, URIs, fields) and never duplicated. Each item is stamped with its KeePass UUID in a <code>KP2BW_ID</code> field, so distinct entries that share a title stay separate and a re-run is matched by identity rather than title. Edits you make in Bitwarden are <b>protected</b>: a re-run preserves them instead of reverting to KeePass (a <code>KP2BW_SYNC</code> content stamp tells your edit apart from kp2bw's own writes); <code>--force-update</code> overrides.<br> Disable updates with <code>--no-update</code>.</details>
- <details><summary><b>Nested folders</b></summary> KeePass folder hierarchy is recreated in Bitwarden.</details>
- <details><summary><b>Recycle Bin filtering</b></summary> Deleted entries are automatically excluded.</details>
- <details><summary><b>Expiry awareness</b></summary> Expired entries are marked <code>[EXPIRED]</code> in notes; optionally skip them entirely with <code>--skip-expired</code>.</details>
- <details><summary><b>Metadata preservation</b></summary> KeePass tags and expiry date are folded into a single <code>KP2BW_META</code> custom field (YAML), omitted when an entry has neither. Created/modified timestamps are not migrated — Bitwarden manages its own creation/revision dates.</details>
- <details><summary><b>Tag filtering</b></summary> Import only entries matching specific tags.</details>
- <details><summary><b>Organization &amp; collection support</b></summary> Upload into a Bitwarden organization with automatic or manual collection assignment.</details>
- <details><summary><b>Full UTF-8 &amp; cross-platform</b></summary> Works on Windows, macOS, and Linux.</details>

> Fork of [jampe/kp2bw].

## Usage/Installation

```bash
# run directly
uvx kp2bw@latest

# install globally with:
uv tool install kp2bw

# update with:
uv tool update kp2bw

kp2bw --version
kp2bw passwords.kdbx
```

or from a GitHub URL (pull requests display a ["🧪 Test this PR"] section with convenience commands to run the branch
without installing):

```bash
# install with:
uv tool install git+https://github.com/kjanat/kp2bw
kp2bw passwords.kdbx

# run directly without installing:
uvx --from git+https://github.com/kjanat/kp2bw kp2bw passwords.kdbx
```

## Prerequisites

Install the [Bitwarden CLI] and log in once before using `kp2bw`:

```bash
# optional: point to a self-hosted instance
bw config server https://your-domain.com/

# log in (only needed once; kp2bw uses `bw unlock` afterwards)
bw login <user>

# ensure you get to a point where you are properly logged in
bw status | jq . # jq optional but makes it easier to read the JSON output
```

```jsonc
// Example return value:
{
	"serverUrl": "https://bitwarden.example.com",
	"lastSync": "2020-06-16T06:33:51.419Z",
	"userEmail": "user@example.com",
	"userId": "00000000-0000-0000-0000-000000000000",
	"status": "locked",
}
```

## Usage

```pwsh
kp2bw [-h] [-V] [-k PASSWORD] [-K FILE] [-b PASSWORD] [-o ID]
       [-t TAG [TAG ...]] [-c ID] [--path-to-name | --no-path-to-name]
       [--path-to-name-skip N] [--skip-expired | --no-skip-expired]
       [--include-recycle-bin | --no-include-recycle-bin]
       [--metadata | --no-metadata] [--update | --no-update] [--force-update]
       [--include-oversize-secrets] [--folder | --no-folder] [--uri-match MODE]
       [--interpret-uri-syntax | --no-interpret-uri-syntax]
       [--migrate-uris] [--report-uris SOURCE] [--strip-ids] [-y] [-v] [-d]
       [FILE]
```

| Flag                                   | Description                                                                                                               | Env var                               |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `keepass_file`                         | Path to your KeePass 2.x database                                                                                         | `KP2BW_KEEPASS_FILE`                  |
| `-k, --keepass-password`               | KeePass password (prompted if omitted)                                                                                    | `KP2BW_KEEPASS_PASSWORD`              |
| `-K, --keepass-keyfile`                | KeePass key file                                                                                                          | `KP2BW_KEEPASS_KEYFILE`               |
| `-b, --bitwarden-password`             | Bitwarden password (prompted if omitted)                                                                                  | `KP2BW_BITWARDEN_PASSWORD`            |
| `-o, --bitwarden-org`                  | Bitwarden Organization ID                                                                                                 | `KP2BW_BITWARDEN_ORG`                 |
| `-c, --bitwarden-collection`           | Collection ID, `auto` for top-level folder names, or `nested` for full folder paths                                       | `KP2BW_BITWARDEN_COLLECTION`          |
| `-t, --import-tags`                    | Only import entries with these tags                                                                                       | `KP2BW_IMPORT_TAGS` (comma-separated) |
| `--folder` / `--no-folder`             | Create personal Bitwarden folders from KeePass groups (default: on, but off when `--bitwarden-org` is set)                | `KP2BW_CREATE_FOLDERS`                |
| `--path-to-name` / `--no-path-to-name` | Prepend folder path to entry names (default: off)                                                                         | `KP2BW_PATH_TO_NAME`                  |
| `--path-to-name-skip`                  | Skip first N folders in path prefix (default: 1)                                                                          | `KP2BW_PATH_TO_NAME_SKIP`             |
| `--skip-expired`                       | Skip entries that have expired in KeePass                                                                                 | `KP2BW_SKIP_EXPIRED`                  |
| `--include-recycle-bin`                | Include Recycle Bin entries (excluded by default)                                                                         | `KP2BW_INCLUDE_RECYCLE_BIN`           |
| `--metadata` / `--no-metadata`         | Toggle KeePass tags/expiry as a `KP2BW_META` field (default: on)                                                          | `KP2BW_MIGRATE_METADATA`              |
| `--update` / `--no-update`             | Update existing entries changed in KeePass (default: on)                                                                  | `KP2BW_UPDATE`                        |
| `--force-update`                       | Overwrite items even if edited in Bitwarden since the last run (default: protect such edits)                              | `KP2BW_FORCE_UPDATE`                  |
| `--include-oversize-secrets`           | Offload over-limit secret fields[^offload] to a `.txt` attachment instead of dropping them (default: off)                 | `KP2BW_INCLUDE_OVERSIZE_SECRETS`      |
| `--uri-match MODE`                     | Match mode for plain URLs: `default`(default, account default)/`domain`/`host`/`startswith`/`exact`/`regex`/`never`       | `KP2BW_URI_MATCH`                     |
| `--interpret-uri-syntax`               | Honor KeePassXC quote/wildcard URL syntax on additional URLs (default: on; `--no-…` for literal)                          | `KP2BW_INTERPRET_URI_SYNTAX`          |
| `--migrate-uris`                       | Upgrade existing items: re-fold legacy `KP2A_URL*`/`AndroidApp` fields into login URIs, then exit (no KeePass)            | `KP2BW_MIGRATE_URIS`                  |
| `--report-uris SOURCE`                 | Print a read-only URI collision report (`keepass` or `bitwarden`) and exit; lists registrable domains with multiple hosts | `KP2BW_REPORT_URIS`                   |
| `--strip-ids`                          | Finalize: remove the `KP2BW_ID`/`KP2BW_SYNC` stamps from migrated items, then exit (no migration; no KeePass db)          | `KP2BW_STRIP_IDS`                     |
| `-y, --yes`                            | Skip the Bitwarden CLI setup confirmation prompt                                                                          | `KP2BW_YES`                           |
| `-v, --verbose`                        | Verbose output                                                                                                            | `KP2BW_VERBOSE`                       |
| `-d, --debug`                          | Debug output — includes third-party library logs                                                                          | `KP2BW_DEBUG`                         |
| `-V, --version`                        | Print the installed `kp2bw` version and exit                                                                              | -                                     |

Configuration precedence is always: CLI flag > environment variable > built-in default.

### Organization collections

Bitwarden folders are personal-vault metadata. When importing into an organization, use `--bitwarden-collection auto` to
create/use one collection per top-level KeePass folder, or `--bitwarden-collection nested` to create/use collections
from full KeePass paths such as `Work/Servers`.

Because folders only duplicate the collection tree in your personal vault, `--bitwarden-org` defaults to **not**
creating personal folders — items are filed only into collections. Pass `--folder` (or `KP2BW_CREATE_FOLDERS=1`) to
restore the personal folder tree alongside the collections.

### URL handling

A KeePass(XC) entry's additional URLs (`KP2A_URL`/`KP2A_URL_n`, plus the plainer `URL`/`URL_n` convention) and Android
packages (`AndroidApp`/`AndroidApp_n`, incl. the no-underscore `AndroidApp1` variant) are migrated as real Bitwarden
**login URIs** — not inert custom fields — so one login autofills across every site and app it covered in KeePass.
Free-text URL labels (`API Url`, `Alt. URL`, `Website`, …) are left as custom fields, since folding those would wrongly
autofill API endpoints and other metadata. Each URI gets a per-URI match mode reproducing KeePassXC's behaviour: a plain
URL → **account default** (`match` unset, what Bitwarden itself writes; pass `--uri-match domain` to force base-domain
and replicate KeePassXC's host-based matching), a double-quoted URL → **exact**, and a `*` wildcard → **starts-with**
(trailing path) or **regex**. Non-web schemes (`keepassxc://`, `cmd://`, `kdbx://`, `file://`) and unresolved `{REF:…}`
URLs are dropped. `--no-interpret-uri-syntax` disables the quote/wildcard interpretation and imports every URL as a
plain string.

Already imported before this existed? Two ways to upgrade: re-run a normal migration (the change is detected and the
items are updated in place), or — if you don't want to re-import — run `kp2bw --migrate-uris`, a Bitwarden-only one-shot
pass that re-folds the legacy fields into URIs on every existing item. Both honour
`--uri-match`/`--interpret-uri-syntax` and `-o`/`-c`.

Too many subdomains autofilling together? Under base-domain matching, every login under `*.example.com` surfaces on any
`example.com` subdomain. `kp2bw --report-uris keepass` (or `bitwarden`) prints a read-only collision report —
registrable domains with multiple hosts — so you can see which entries pile up and switch those to **Host** match (or
flip your Bitwarden account's default URI match detection to Host). It changes nothing; it just lists.

Because kp2bw is KeePass-authoritative, a re-run would normally overwrite any difference on an existing item — quietly
undoing a title, note or URI you fixed in Bitwarden. It doesn't: every item kp2bw writes carries a `KP2BW_SYNC` content
signature, and a re-run that finds an item's current content no longer matching that stamp knows *you* edited it
(kp2bw's own writes restamp, so they never self-trip) and **preserves your edit**, listing it as `protected` in the
summary. Pass `--force-update` (env `KP2BW_FORCE_UPDATE`) to make KeePass win regardless. Unchanged re-runs stay
idempotent, and items imported before this existed are adopted normally on their first re-run.

Every migrated item carries a plain-text `KP2BW_ID` custom field — the KeePass UUID kp2bw uses to match entries on
re-runs so nothing duplicates. Once you're satisfied the migration is complete and you're ready to fully adopt
Bitwarden, run

```bash
kp2bw --strip-ids            # personal vault; add -o/-c to scope to an org/collection
```

to remove that stamp from every migrated item and exit. No KeePass database is read.

> [!WARNING]
> This is **irreversible** and makes future migration re-runs unreliable. Without the stamp, a re-run can only match by
> folder + name — the exact collision the stamp exists to prevent — so entries that share a folder and title may be
> duplicated or mismatched on a later migration. `--strip-ids` confirms before changing anything (skip with `-y`). Only
> run it once you're truly done migrating.

### `.env` file

kp2bw automatically loads a `.env` file, searched upward from the current working directory, so you can keep your
settings (including the database path via `KP2BW_KEEPASS_FILE`) out of your shell history.

Copy [`.env.example`] to `.env` and uncomment what you need:

```env
KP2BW_KEEPASS_FILE=passwords.kdbx
KP2BW_BITWARDEN_ORG=00000000-0000-0000-0000-000000000000
KP2BW_SKIP_EXPIRED=1
```

Then just run `kp2bw` with no arguments. A real shell environment variable still overrides any value in `.env`
(precedence is unchanged: CLI flag > env var > default), and `.env` is gitignored so secrets stay local.

## Troubleshooting

Every run writes a full DEBUG log to a per-user file even when the console stays quiet, so a failed run leaves a
complete record to share. On Windows that is `%LOCALAPPDATA%\kp2bw\logs`; override the file with `KP2BW_LOG_FILE` or the
directory with `KP2BW_LOG_DIR`. `bw serve` errors include the server's actual message, and a slow or dropped request no
longer aborts the run — failed entries are counted in the summary and a re-run safely picks up where it left off.
Against a slow self-hosted server (e.g. Vaultwarden) where individual writes time out, raise the per-request HTTP
timeout with `KP2BW_HTTP_TIMEOUT` (seconds; default 180, capped at 3600) to let those creates finish in the first place.

See [TROUBLESHOOTING].

[^offload]: Bitwarden has a 10k character limit for text fields.

    kp2bw can offload any field exceeding that limit (hidden OTP secrets, passkey attributes, KeePass-protected fields)
    to a `.txt` file attachment instead of dropping it, so you don't lose data. This applies to long notes as well as
    custom fields.

["🧪 Test this PR"]: https://github.com/kjanat/kp2bw/pull/34#issuecomment-4763225590 "Example"
[Bitwarden CLI]: https://bitwarden.com/help/cli/
[TROUBLESHOOTING]: ./TROUBLESHOOTING.md
[`.env.example`]: ./.env.example
[jampe/kp2bw]: https://github.com/jampe/kp2bw
