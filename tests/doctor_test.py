"""``kp2bw --doctor``: report collection, redaction, and rendering."""

from dataclasses import replace
from pathlib import Path

from kp2bw import __version__
from kp2bw.doctor import DoctorReport, collect_report, redact_report, render_report

_BASE = DoctorReport(
    kp2bw_version="1.2.3",
    revision="0123456789abcdef0123456789abcdef01234567",
    revision_source="git checkout",
    install_method="uv (editable checkout)",
    python_version="3.14.0",
    platform="linux",
    dotenv_path=str(Path.home() / "proj" / ".env"),
    bw_command=str(Path.home() / ".local" / "bin" / "bw"),
    bw_version="2026.6.0",
    bw_serve_supported=True,
    bw_server_url="https://vault.example.org",
    server_product="Vaultwarden 1.37.0",
)


def assert_redact_masks_self_hosted_url_and_home_paths() -> None:
    redacted = redact_report(_BASE)
    if redacted.bw_server_url != "https://<redacted self-hosted>":
        raise AssertionError(
            f"self-hosted URL must be masked: {redacted.bw_server_url}"
        )
    if redacted.dotenv_path != "~/proj/.env":
        raise AssertionError(f".env path must be home-relative: {redacted.dotenv_path}")
    if redacted.bw_command != "~/.local/bin/bw":
        raise AssertionError(f"bw path must be home-relative: {redacted.bw_command}")
    if redacted.server_product != _BASE.server_product:
        raise AssertionError("the server product identifies software, keep it")
    if str(Path.home()) in "\n".join(str(line) for line in render_report(redacted)):
        raise AssertionError("rendered redacted report must not contain the home dir")


def assert_redact_keeps_official_cloud_hosts() -> None:
    cloud = replace(_BASE, bw_server_url="https://vault.bitwarden.com")
    if redact_report(cloud).bw_server_url != "https://vault.bitwarden.com":
        raise AssertionError("official Bitwarden hosts identify the tier, keep them")


def assert_render_includes_versions_and_support_links() -> None:
    lines = render_report(_BASE)
    text = "\n".join(str(line) for line in lines)
    for needle in (
        "1.2.3",
        "0123456789ab (git checkout)",
        "2026.6.0",
        "Vaultwarden 1.37.0",
        "https://github.com/kjanat/kp2bw/issues",
    ):
        if needle not in text:
            raise AssertionError(f"rendered report must mention {needle!r}:\n{text}")
    if _BASE.revision is not None and _BASE.revision in text:
        raise AssertionError("the full sha must render short, not inline")
    commit_url = f"https://github.com/kjanat/kp2bw/commit/{_BASE.revision}"
    if not any(commit_url in str(span.style) for line in lines for span in line.spans):
        raise AssertionError("the short sha must hyperlink to the full commit URL")


def assert_missing_bw_is_unhealthy() -> None:
    broken = replace(
        _BASE,
        bw_command=None,
        bw_version=None,
        bw_serve_supported=None,
        bw_server_url=None,
        server_product=None,
    )
    if broken.healthy:
        raise AssertionError("a report without a usable bw CLI must be unhealthy")
    text = "\n".join(str(line) for line in render_report(broken))
    if "NOT FOUND on PATH" not in text:
        raise AssertionError(f"missing bw must be called out:\n{text}")


def assert_collect_report_shape() -> None:
    report = collect_report()
    if report.kp2bw_version != __version__:
        raise AssertionError(f"unexpected kp2bw version: {report.kp2bw_version}")
    data = report.as_dict()
    if set(data) != {
        "kp2bw_version",
        "revision",
        "revision_source",
        "install_method",
        "python_version",
        "platform",
        "dotenv_path",
        "bw_command",
        "bw_version",
        "bw_serve_supported",
        "bw_server_url",
        "server_product",
    }:
        raise AssertionError(f"unexpected report keys: {sorted(data)}")


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_redact_masks_self_hosted_url_and_home_paths()
    assert_redact_keeps_official_cloud_hosts()
    assert_render_includes_versions_and_support_links()
    assert_missing_bw_is_unhealthy()
    assert_collect_report_shape()
    print("doctor test passed")


if __name__ == "__main__":
    main()
