# KP2BW - KeePass 2.x to Bitwarden Converter

> Fork of [jampe/kp2bw], modernized.

Migrates KeePass databases to Bitwarden via the `bw` CLI, with advantages over
the built-in Bitwarden importer:

- **Encrypted in-memory transfer** -- data never hits disk unencrypted (except
  attachments, which are cleaned up after upload)
- **KeePass REF resolution** -- username/password references are resolved:
  matching credentials merge URLs into one entry; differing ones create new
  entries
- **Passkey migration** -- KeePassXC FIDO2/passkey credentials
  (`KPEX_PASSKEY_*`) are converted to Bitwarden `fido2Credentials`
- **Custom properties & attachments** -- imported as Bitwarden custom fields or
  attachments (values > 10k chars auto-upload as files)
- **Long notes handling** -- notes exceeding 10k chars are uploaded as
  `notes.txt` attachments
- **Idempotent** -- safe to run multiple times without duplicating entries
- **Nested folders** -- KeePass folder hierarchy is recreated in Bitwarden
- **Recycle Bin filtering** -- deleted entries are automatically excluded
- **Expiry awareness** -- expired entries are marked `[EXPIRED]` in notes;
  optionally skip them entirely with `--skip-expired`
- **Metadata preservation** -- KeePass tags, expiry dates, and created/modified
  timestamps are stored as Bitwarden custom fields
- **Tag filtering** -- import only entries matching specific tags
- **Organization & collection support** -- upload into a Bitwarden organization
  with automatic or manual collection assignment
- **Full UTF-8 & cross-platform** -- works on Windows, macOS, and Linux

## Installation

```bash
# install with:
uv tool install kp2bw
kp2bw passwords.kdbx

# or run directly without installing:
uvx kp2bw
```

or from a GitHub URL:

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
```

## Usage

```console
kp2bw [-h] [-V] [-k PASSWORD] [-K FILE] [-b PASSWORD] [-o ID]
       [-t TAG [TAG ...]] [-c ID] [--path-to-name | --no-path-to-name]
       [--path-to-name-skip N] [--skip-expired | --no-skip-expired]
       [--include-recycle-bin | --no-include-recycle-bin]
       [--metadata | --no-metadata] [-y] [-v] [-d]
       FILE
```

| Flag                                   | Description                                                    | Env var                               |
| -------------------------------------- | -------------------------------------------------------------- | ------------------------------------- |
| `keepass_file`                         | Path to your KeePass 2.x database                              | -                                     |
| `-k, --keepass-password`               | KeePass password (prompted if omitted)                         | `KP2BW_KEEPASS_PASSWORD`              |
| `-K, --keepass-keyfile`                | KeePass key file                                               | `KP2BW_KEEPASS_KEYFILE`               |
| `-b, --bitwarden-password`             | Bitwarden password (prompted if omitted)                       | `KP2BW_BITWARDEN_PASSWORD`            |
| `-o, --bitwarden-org`                  | Bitwarden Organization ID                                      | `KP2BW_BITWARDEN_ORG`                 |
| `-c, --bitwarden-collection`           | Collection ID, or `auto` to derive from top-level folder names | `KP2BW_BITWARDEN_COLLECTION`          |
| `-t, --import-tags`                    | Only import entries with these tags                            | `KP2BW_IMPORT_TAGS` (comma-separated) |
| `--path-to-name` / `--no-path-to-name` | Prepend folder path to entry names (default: off)              | `KP2BW_PATH_TO_NAME`                  |
| `--path-to-name-skip`                  | Skip first N folders in path prefix (default: 1)               | `KP2BW_PATH_TO_NAME_SKIP`             |
| `--skip-expired`                       | Skip entries that have expired in KeePass                      | `KP2BW_SKIP_EXPIRED`                  |
| `--include-recycle-bin`                | Include Recycle Bin entries (excluded by default)              | `KP2BW_INCLUDE_RECYCLE_BIN`           |
| `--metadata` / `--no-metadata`         | Toggle KeePass metadata as custom fields (default: on)         | `KP2BW_MIGRATE_METADATA`              |
| `-y, --yes`                            | Skip the Bitwarden CLI setup confirmation prompt               | `KP2BW_YES`                           |
| `-v, --verbose`                        | Verbose output                                                 | `KP2BW_VERBOSE`                       |
| `-d, --debug`                          | Debug output — includes third-party library logs               | `KP2BW_DEBUG`                         |
| `-V, --version`                        | Print the installed `kp2bw` version and exit                   | -                                     |

Configuration precedence is always: CLI flag > environment variable > built-in default.

## Troubleshooting

### "Invalid master password" on `bw unlock`

If your password contains special shell characters (`?`, `>`, `&`, etc.), wrap
it in double quotes when prompted. See jampe/kp2bw#10 and
libkeepass/pykeepass#254 for details.

### `bw serve` startup timeout

kp2bw starts `bw serve` on a random localhost port. If it times out after 60s:

- Check that `bw` is installed and on your `PATH`
- Run `bw login` once if you haven't already
- Ensure no firewall rules block localhost connections
- Try `bw serve --port 8087 --hostname 127.0.0.1` manually to see if it starts

### Items skipped unexpectedly during org import

When importing with `--bitwarden-org`, items already present in the
organization vault are skipped. If you're importing into a specific collection
(`--bitwarden-collection`), only items already in *that* collection are
considered duplicates — items in other collections will be created or updated.

[jampe/kp2bw]: https://github.com/jampe/kp2bw
[Bitwarden CLI]: https://bitwarden.com/help/cli/
