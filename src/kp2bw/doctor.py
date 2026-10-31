"""Environment diagnostics behind ``kp2bw --doctor``.

Collects the facts needed to triage a broken setup -- kp2bw's own version and
source revision, the Python runtime, whether a ``.env`` is picked up, and how
the Bitwarden CLI resolves (path, version, ``serve`` support, configured
server) -- into one structured report. The report doubles as the context
payload for a future error-reporting integration, so collection is separate
from rendering.
"""

import json
import platform
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, replace
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import httpx
from dotenv import find_dotenv
from rich.style import Style
from rich.text import Text

from . import __title__, __version__
from .build_info import BUILD_SHA
from .bw_serve import cli_environment, get_cli_version, resolve_cli_command
from .exceptions import BitwardenClientError

SUBPROCESS_TIMEOUT: int = 30
HTTP_TIMEOUT: int = 10
FULL_SHA: re.Pattern[str] = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class DoctorReport:
    """One structured snapshot of the environment kp2bw runs in."""

    kp2bw_version: str
    revision: str | None
    revision_source: str | None
    install_method: str
    python_version: str
    platform: str
    dotenv_path: str | None
    bw_command: str | None
    bw_version: str | None
    bw_serve_supported: bool | None
    bw_server_url: str | None
    server_product: str | None

    @property
    def healthy(self) -> bool:
        """True when the Bitwarden CLI is usable for a migration."""
        return (
            self.bw_command is not None
            and self.bw_version is not None
            and self.bw_serve_supported is True
        )

    def as_dict(self) -> dict[str, str | bool | None]:
        """The report as plain data, e.g. for an error-report context."""
        return cast(dict[str, str | bool | None], asdict(self))


def read_revision() -> tuple[str, str] | None:
    """The full git sha this kp2bw comes from plus its source, best source first.

    Order: the sha the release workflow baked into the wheel, the commit
    recorded by a ``pip``/``uv`` VCS install (``direct_url.json``), and finally
    the live revision of a source checkout.
    """
    if BUILD_SHA:
        return (BUILD_SHA, "baked at build")

    try:
        direct_url = distribution(__title__).read_text("direct_url.json")
    except PackageNotFoundError:
        direct_url = None
    if direct_url is not None:
        try:
            parsed = cast(dict[str, object], json.loads(direct_url))
        except ValueError:
            parsed = {}
        vcs_info = parsed.get("vcs_info")
        if isinstance(vcs_info, dict):
            commit = cast(dict[str, object], vcs_info).get("commit_id")
            if isinstance(commit, str) and commit:
                return (commit, "vcs install")

    package_dir = Path(__file__).resolve().parent
    for parent in (package_dir, *package_dir.parents):
        if not (parent / ".git").exists():
            continue
        try:
            result = subprocess.run(
                ["git", "-C", str(parent), "rev-parse", "HEAD"],
                check=False,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                stdin=subprocess.DEVNULL,
            )
        except OSError, subprocess.TimeoutExpired:
            return None
        revision = result.stdout.strip()
        if result.returncode == 0 and revision:
            return (revision, "git checkout")
        return None
    return None


def install_method() -> str:
    """How this kp2bw got installed: pip/uv/pipx, tool-managed, or editable."""
    try:
        dist = distribution(__title__)
    except PackageNotFoundError:
        return "unknown"
    installer = (dist.read_text("INSTALLER") or "").strip() or "unknown"

    markers: list[str] = []
    direct_url = dist.read_text("direct_url.json")
    if direct_url is not None:
        try:
            parsed = cast(dict[str, object], json.loads(direct_url))
        except ValueError:
            parsed = {}
        dir_info = parsed.get("dir_info")
        if isinstance(dir_info, dict):
            if cast(dict[str, object], dir_info).get("editable") is True:
                markers.append("editable checkout")
            else:
                markers.append("local directory")

    prefix = Path(sys.prefix).as_posix()
    if "/pipx/" in prefix or prefix.endswith("/pipx"):
        markers.append("pipx environment")
    elif "/uv/tools/" in prefix:
        markers.append("uv tool environment")

    return f"{installer} ({', '.join(markers)})" if markers else installer


def identify_server_product(server_url: str) -> str:
    """Identify the server behind *server_url* via its anonymous ``/api/config``."""
    try:
        response = httpx.get(f"{server_url}/api/config", timeout=HTTP_TIMEOUT)
        _ = response.raise_for_status()
        config = cast(dict[str, object], response.json())
    except (httpx.HTTPError, ValueError) as exc:
        return f"unreachable ({type(exc).__name__})"
    server = config.get("server")
    name = (
        cast(dict[str, object], server).get("name")
        if isinstance(server, dict)
        else None
    )
    version = config.get("version")
    return f"{name or 'Bitwarden'} {version or '(unknown version)'}"


def cli_output(cli_command: list[str], cli_cwd: str | None, *args: str) -> str | None:
    """Stdout of one diagnostic ``bw`` subcommand, or ``None`` on failure."""
    try:
        result = subprocess.run(
            [*cli_command, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            stdin=subprocess.DEVNULL,
            cwd=cli_cwd,
            env=cli_environment(command=cli_command),
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def collect_report() -> DoctorReport:
    """Gather the full :class:`DoctorReport` for the current environment."""
    dotenv_path = find_dotenv(usecwd=True) or None

    cli_command: list[str] | None
    cli_cwd: str | None
    try:
        cli_command, cli_cwd = resolve_cli_command()
    except BitwardenClientError:
        cli_command, cli_cwd = None, None

    bw_version: str | None = None
    bw_serve_supported: bool | None = None
    bw_server_url: str | None = None
    server_product: str | None = None
    if cli_command is not None:
        bw_version = get_cli_version(cli_command, cli_cwd)
        bw_serve_supported = (
            cli_output(cli_command, cli_cwd, "serve", "--help") is not None
        )
        server = cli_output(cli_command, cli_cwd, "config", "server")
        if server and server.startswith(("http://", "https://")):
            bw_server_url = server
            server_product = identify_server_product(server)

    revision = read_revision()
    return DoctorReport(
        kp2bw_version=__version__,
        revision=revision[0] if revision else None,
        revision_source=revision[1] if revision else None,
        install_method=install_method(),
        python_version=platform.python_version(),
        platform=sys.platform,
        dotenv_path=dotenv_path,
        bw_command=" ".join(cli_command) if cli_command else None,
        bw_version=bw_version,
        bw_serve_supported=bw_serve_supported,
        bw_server_url=bw_server_url,
        server_product=server_product,
    )


def redact_report(report: DoctorReport) -> DoctorReport:
    """The same report with the server URL and home-anchored paths masked.

    Bitwarden's own cloud hosts stay visible (they identify the product tier,
    not the user); any other host is masked as self-hosted. Paths under the
    user's home directory are shortened to ``~`` so a pasted report does not
    leak the account name.
    """
    home = str(Path.home())

    def strip_home(path: str | None) -> str | None:
        if path and path.startswith(home):
            return f"~{path[len(home) :]}"
        return path

    url = report.bw_server_url
    if url:
        host = urlsplit(url).hostname or ""
        official = host in {"bitwarden.com", "bitwarden.eu"} or host.endswith((
            ".bitwarden.com",
            ".bitwarden.eu",
        ))
        if not official:
            url = "https://<redacted self-hosted>"

    return replace(
        report,
        dotenv_path=strip_home(report.dotenv_path),
        bw_command=strip_home(report.bw_command),
        bw_server_url=url,
    )


def revision_text(report: DoctorReport) -> Text:
    """The revision rendered short, hyperlinked to the commit when it is a sha."""
    if not report.revision:
        return Text("unknown")
    short = report.revision[:12]
    if FULL_SHA.fullmatch(report.revision):
        text = Text(
            short,
            style=Style(
                link=f"https://github.com/kjanat/kp2bw/commit/{report.revision}"
            ),
        )
    else:
        text = Text(short)
    if report.revision_source:
        text.append(f" ({report.revision_source})")
    return text


def render_report(report: DoctorReport) -> list[Text]:
    """The report as aligned, human-readable lines."""
    serve: str
    if report.bw_serve_supported is None:
        serve = "unknown"
    else:
        serve = "supported" if report.bw_serve_supported else "unsupported"
    rows: tuple[tuple[str, Text], ...] = (
        (__title__, Text(report.kp2bw_version)),
        ("revision", revision_text(report)),
        ("installed via", Text(report.install_method)),
        ("python", Text(f"{report.python_version} ({report.platform})")),
        (".env", Text(report.dotenv_path or "none detected")),
        ("CLI", Text(report.bw_command or "NOT FOUND on PATH")),
        ("CLI version", Text(report.bw_version or "unknown")),
        ("serve", Text(serve)),
        ("server URL", Text(report.bw_server_url or "not configured")),
        ("server", Text(report.server_product or "unknown")),
    )
    width = max(len(label) for label, _ in rows)
    lines = [Text(f"{label.ljust(width)}  ") + value for label, value in rows]
    lines.extend([
        Text(""),
        Text("Need help? Include this report when you open an issue:"),
        Text("  issues        https://github.com/kjanat/kp2bw/issues"),
        Text("  pull requests https://github.com/kjanat/kp2bw/pulls"),
    ])
    return lines
