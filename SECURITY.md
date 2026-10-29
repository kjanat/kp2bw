# Security policy

kp2bw handles KeePass databases, vault credentials, passkeys and attachments. Report suspected vulnerabilities
privately, including integrity or data-loss problems with security impact.

## Supported versions

Security fixes target the latest stable kp2bw release and are delivered in a new release. Upgrade to that release when a
fix is available. Older releases do not have a maintained security backport stream or a guaranteed support window.

Prereleases are for testing and do not receive a separate security maintenance stream. Reports affecting a prerelease or
the development branch are welcome; fixes land in subsequent development or release builds. Reports about older versions
are also welcome, especially when the problem may still affect the latest release.

This policy covers the distributed Python package and project-published container images when available. A pulled image
does not update itself: pull and deploy a newly published fixed image. A pinned digest continues to identify the same
build even after a newer release becomes available.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/kjanat/kp2bw/security/advisories/new). You must sign in
to GitHub. Reports are shared privately with the repository's security advisory maintainers. Do not open a public issue
or pull request containing undisclosed exploit details or sensitive evidence.

Include the following where available; a complete proof of concept is not required to start a report:

- A short summary, expected and observed behaviour, and the security impact.
- kp2bw version and installation method; for containers, the image reference and digest.
- OS and Python version, Bitwarden CLI (or replacement CLI) version, and Bitwarden/Vaultwarden server version.
- Relevant options and configuration with credentials and identifying information removed.
- Reproduction steps using synthetic entries and attachments, including any required permissions or preconditions.
- A minimal synthetic fixture or redacted log excerpt, and whether you reproduced it on the latest version.

Do **not** send real vaults or KeePass databases, passwords, session tokens, private keys, production attachments or
unredacted logs. Use generated test credentials and keys. Inspect evidence before uploading it: logs and error messages
can contain vault content, account identifiers or local paths even when credentials are redacted.

For ordinary bugs and feature requests, use [GitHub issues](https://github.com/kjanat/kp2bw/issues). Data corruption,
missing attachments or unexpected changes can have security impact; report them privately when they compromise
confidentiality, integrity or access boundaries. If unsure, start with a private report.

## Scope and upstream components

kp2bw is responsible for its conversion and migration behaviour, handling of local files and logs, credential and
subprocess handling, and integration of dependencies and bundled tools in its Python package and container images.
Relevant reports include secret disclosure, unsafe handling of input, writing outside the intended vault scope, and loss
or modification of protected data caused by kp2bw.

Bitwarden, Vaultwarden and other dependencies also have their own security processes. If a problem is isolated to an
upstream component, report it through that project's private security channel. The kp2bw maintainer may help identify
the responsible project and discuss coordination with you. A problem in kp2bw's use or packaging of an upstream
component still belongs here; an upstream origin does not automatically exclude a report. Fixes may require an upstream
release, a dependency update or a kp2bw mitigation. This project cannot promise to repair every upstream vulnerability.

## Response and disclosure

This is a maintainer-run project without a guaranteed response or remediation deadline. The maintainer will aim to
acknowledge reports, investigate reproducible impact and discuss next steps in the private advisory thread as
availability permits. If you have not heard back, follow up in that thread.

Please coordinate publication in the private thread so a fix or mitigation and an advisory can be prepared together.
Share any disclosure deadline when reporting; timing and reporter credit should be agreed during triage. Acknowledgement
is not a promise that every report will be confirmed or fixed. Confirmed issues and available fixes can be documented in
a GitHub security advisory and release notes without publishing sensitive report material.
