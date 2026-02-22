# KP2BW - KeePass 2.x to Bitwarden Converter

> Fork of [jampe/kp2bw](https://github.com/jampe/kp2bw), modernized with a
> `src/` layout, `uv` packaging, and Python 3.14+ support.

Migrates KeePass databases to Bitwarden via the `bw` CLI, with advantages over
the built-in Bitwarden importer:

- **Encrypted in-memory transfer** -- data never hits disk unencrypted (except
  attachments, which are cleaned up after upload)
- **KeePass REF resolution** -- username/password references are resolved:
  matching credentials merge URLs into one entry; differing ones create new
  entries
- **Custom properties & attachments** -- imported as Bitwarden custom fields or
  attachments (values > 10k chars auto-upload as files)
- **Long notes handling** -- notes exceeding 10k chars are uploaded as
  `notes.txt` attachments
- **Idempotent** -- safe to run multiple times without duplicating entries
- **Nested folders** -- KeePass folder hierarchy is recreated in Bitwarden
- **Tag filtering** -- import only entries matching specific tags
- **Organization & collection support** -- upload into a Bitwarden organization
  with automatic or manual collection assignment
- **Full UTF-8 & cross-platform** -- works on Windows, macOS, and Linux

## Installation

```bash
uv tool install git+https://github.com/kjanat/kp2bw
```

Or run directly without installing:

```bash
uvx --from git+https://github.com/kjanat/kp2bw kp2bw passwords.kdbx
```

## Prerequisites

Install the [Bitwarden CLI](https://bitwarden.com/help/cli/) and log in once
before using kp2bw:

```bash
# optional: point to a self-hosted instance
bw config server https://your-domain.com/

# log in (only needed once; kp2bw uses `bw unlock` afterwards)
bw login <user>
```

## Usage

```
kp2bw [-h] [-kppw KP_PW] [-kpkf KP_KEYFILE] [-bwpw BW_PW]
       [-bworg BW_ORG] [-bwcoll BW_COLL] [-import_tags TAG ...]
       [-path2name] [-path2nameskip N] [-y] [-v]
       keepass_file
```

| Flag             | Description                                                    |
| ---------------- | -------------------------------------------------------------- |
| `keepass_file`   | Path to your KeePass 2.x database                              |
| `-kppw`          | KeePass password (prompted if omitted)                         |
| `-kpkf`          | KeePass key file                                               |
| `-bwpw`          | Bitwarden password (prompted if omitted)                       |
| `-bworg`         | Bitwarden Organization ID                                      |
| `-bwcoll`        | Collection ID, or `auto` to derive from top-level folder names |
| `-import_tags`   | Only import entries with these tags                            |
| `-path2name`     | Prepend folder path to entry names                             |
| `-path2nameskip` | Skip first N folders in path prefix (default: 1)               |
| `-y`             | Skip the Bitwarden CLI setup confirmation prompt               |
| `-v`             | Verbose output                                                 |

## Troubleshooting

### "Invalid master password" on `bw unlock`

If your password contains special shell characters (`?`, `>`, `&`, etc.), wrap
it in double quotes when prompted. See
[upstream issue discussion](https://github.com/jampe/kp2bw/issues) for details.
