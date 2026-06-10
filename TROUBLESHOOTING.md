# Troubleshooting

## `kp2bw` outdated

[![GitHub Release](https://img.shields.io/github/v/release/kjanat/kp2bw)][kp2bw:release:latest]

If you installed `kp2bw` a while ago, you may be running into an issue that's already been fixed.\
Check your version with `kp2bw --version` and compare it to the latest release on GitHub.

If you're outdated, update to the latest version and try again.

## Windows: "untrusted mount point" (os error 448) from `uv` / `uvx`

If `uvx kp2bw`, `uv run kp2bw` or even a plain `uv sync` dies before kp2bw starts with:

```console
error: Failed to inspect Python interpreter from managed installations at
       `C:\Users\<you>\AppData\Roaming\uv\python\cpython-3.14-windows-x86_64-none\python.exe`
  Caused by: Failed to query Python interpreter
  Caused by: failed to query metadata of file `...\python.exe`: The path cannot be traversed
             because it contains an untrusted mount point. (os error 448)
```

nothing is wrong with kp2bw or your vault. Windows is refusing to follow a directory junction that uv relies on.

uv keeps each managed Python in a versioned directory (`cpython-3.14.4-windows-x86_64-none`) and points a minor-version
junction (`cpython-3.14-windows-x86_64-none`) at it. Windows hardening around mount-point traversal (reported in the
wild since spring 2026, often alongside the OneDrive Files On-Demand filter; see [uv#19616] and [warp#9044]) can flag a
previously created junction as untrusted, after which *every* process gets error 448 when crossing it. The Python
installation behind the junction is intact.

The fix is to recreate the junctions: a freshly created one is trusted again. In PowerShell:

```powershell
Get-ChildItem "$env:APPDATA\uv\python" -Force |
    Where-Object LinkType -eq 'Junction' |
    ForEach-Object {
        $target = $_.Target
        $_.Delete()
        New-Item -ItemType Junction -Path $_.FullName -Target $target | Out-Null
    }
```

Then re-run the command that failed. If the error returns after a Windows update or a new `uv python install`, run the
snippet again.

## `bw` not found on `PATH`

kp2bw shells out to the [Bitwarden CLI]. If `bw` isn't installed or isn't on your `PATH`, kp2bw stops before prompting
for any passwords with:

```console
ERROR: Bitwarden CLI ('bw') not found on your PATH. ...
```

Install the CLI and make sure `bw --version` runs in the same shell, then retry.

## Login fails with a 404 (self-hosted server too old for your `bw` CLI)

Recent Bitwarden clients — the **2026.x** family, which includes the `bw` CLI that kp2bw drives — log in through a newer
endpoint, `POST /identity/accounts/prelogin/password`.\
A self-hosted server that predates that endpoint has no route for it and answers **404**, so login fails before any
migration starts. A 404 here means "no such route", **not** "wrong password" — don't go hunting for a credential typo.

Compatibility cutoff by server:

- **Vaultwarden:** the endpoint landed in **1.36.0** (released 2026-05-03, [vaultwarden#7156]).\
  Anything older (1.35.x and below) 404s against a current `bw` CLI. Upgrade to [Vaultwarden 1.36.0] or newer.
- **Self-hosted Bitwarden:** update the server image to a build that implements the endpoint.
- **Bitwarden cloud** (`bitwarden.com` / `bitwarden.eu`): always current — unaffected.

The durable fix is to upgrade the server — do that when you can.

If you genuinely can't right now, the workaround is an **older `bw` CLI version**, used for *both* `bw login` and the
migration. This is about the CLI's version, not how it's installed: `bw login` always performs prelogin, so every CLI
needs that endpoint. An older CLI works because it speaks the *legacy* route `/identity/accounts/prelogin`, which your
pre-1.36.0 server already serves; only the newer `/identity/accounts/prelogin/password` route is missing. So you pin the
version — a global install doesn't "skip" the auth endpoint, it just happens to be old enough to use the route the
server has.

There's no clean version cutoff to hand you. Bitwarden shipped several client↔server breaks in this window (for example
a "KDF config is required" change in early-2025 clients), so a CLI old enough to dodge the prelogin 404 can trip a
*different* incompatibility. Expect trial and error and treat this as a stopgap: list versions with

```bash
npm view @bitwarden/cli versions
```

(the CLI ships as [`@bitwarden/cli`][bw:versions] on npm) and work backwards until login succeeds.

kp2bw runs whatever `bw` is on your `PATH`, so the version you settle on has to *be* that `bw`. Install it globally and
use the same CLI for the manual login step too:

```shell
npm install -g @bitwarden/cli@<version>
bw --version                                  # confirm the pinned one is active
bw config server https://vault.example.com
bw login <user>                               # uses the legacy prelogin route
```

To trial a version without disturbing a global install, run it through `npx` — but `npx` does **not** put `bw` on your
`PATH`, so kp2bw can't use it for the migration; it's only good for probing which version logs in:

```shell
npx --package @bitwarden/cli@<version> bw login <user>
```

Either way you stay frozen behind newer clients until the server is upgraded, so upgrade when you can.

## "Invalid master password" on `bw unlock`

If your password contains special shell characters (`?`, `>`, `&`, etc.), wrap it in double quotes when prompted. See
jampe/kp2bw#10 and libkeepass/pykeepass#254 for details.

## `bw serve` startup timeout

kp2bw starts `bw serve` on a random localhost port. If it times out after 60s:

- Check that `bw` is installed and on your `PATH`
- Run `bw login` once if you haven't already
- Ensure no firewall rules block localhost connections
- Try `bw serve --port 8087 --hostname 127.0.0.1` manually to see if it starts

## Items skipped unexpectedly during org import

When importing with `--bitwarden-org`, items already present in the organization vault are matched by folder + name. If
you're importing into a specific collection (`--bitwarden-collection`), only items already in *that* collection are
matched -- items in other collections are created.

## Re-running to pick up KeePass changes

Re-running `kp2bw` against the same database updates matched entries in place when their KeePass content changed (notes,
password, username, URIs or custom fields), so you no longer need to purge the vault to push edits. Unchanged entries
are left untouched. A re-run also uploads any `notes.txt` / long-field / file attachment that a previously imported
entry was missing, and refreshes one whose contents changed in KeePass even when it keeps the same filename (the stale
copy is removed only once the new one has uploaded). Pass `--no-update` (or `KP2BW_UPDATE=0`) to keep the old skip-only
behavior and preserve manual Bitwarden-side edits.

## An attachment failed to upload

Attachment uploads are sent through `bw serve`, which forwards them to your Bitwarden/Vaultwarden server. A rejected
file (for example, an image too large for your plan, or an upload that needs premium/organization storage) now reports
the server's actual message and is skipped -- it no longer aborts the whole migration, so the rest of your entries still
import. Resolve the underlying limit and re-run to upload the remaining files.

[Bitwarden CLI]: https://bitwarden.com/help/cli/
[Vaultwarden 1.36.0]: https://github.com/dani-garcia/vaultwarden/releases/tag/1.36.0
[bw:versions]: https://npm.im/package/@bitwarden/cli?activeTab=versions "@bitwarden/cli | npm versions tab"
[kp2bw:release:latest]: https://github.com/kjanat/kp2bw/releases/latest
[uv#19616]: https://github.com/astral-sh/uv/issues/19616
[vaultwarden#7156]: https://github.com/dani-garcia/vaultwarden/pull/7156
[warp#9044]: https://github.com/warpdotdev/warp/issues/9044
