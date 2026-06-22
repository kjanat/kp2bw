# kp2bw Migration Planner

This docs site helps you choose the safest KeePass-to-Bitwarden migration shape
before running `kp2bw`.

Open these pages in the docs site:

- [Migration planner](./src/routes/+page.svelte) (served at `/`): choose
  options, preview the trees, copy the command.
- [Detailed option guide](./src/routes/docs/+page.svelte) (served at `/docs`):
  learn what each choice means before running it.

The planner shows the source KeePass tree beside the Bitwarden result tree and
turns your choices into the exact `.env` values and `kp2bw` command to run.

## What It Helps Decide

- Personal vault import with folders, or a flat personal import.
- Organization import into nested collections, top-level collections, one fixed
  collection, or no generated hierarchy.
- Whether an organization import should also create personal folders with
  `--folder`.
- Whether a rerun should protect Bitwarden edits, skip updates, or force KeePass
  to win.
- Which tags, expired entries, and Recycle Bin entries are included.

## Important Defaults

- Personal vault is the no-flag default: `kp2bw vault.kdbx`.
- Organization imports default to collections only; personal folders stay off
  unless `--folder` is selected.
- Expired entries are included unless `--skip-expired` is selected.
- Recycle Bin entries are excluded unless `--include-recycle-bin` is selected.
- Tag-filtered commands include `--` before the KeePass file so the file path is
  not parsed as another tag.
