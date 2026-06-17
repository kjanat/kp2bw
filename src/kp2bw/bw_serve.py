"""Bitwarden CLI serve process lifecycle and HTTP transport."""

import asyncio
import atexit
import copy
import logging
import ntpath
import os
import shutil
import signal
import socket
import subprocess
import time
from collections.abc import Callable, Mapping
from types import FrameType, TracebackType
from typing import Any, NamedTuple, Self, cast

import httpx
from rich.markup import escape

from . import VERBOSE
from ._console import console
from .bw_types import BwCollection, BwFolder, BwItemCreate, BwItemResponse
from .exceptions import BitwardenClientError
from .uri_mapping import UriMatchValue, remap_item_fields_to_uris

logger = logging.getLogger(__name__)

# How long to wait for `bw serve` to become responsive.
_SERVE_STARTUP_TIMEOUT_S: float = 60.0

# Polling interval when waiting for serve to start.
_SERVE_POLL_INTERVAL_S: float = 0.25

# Default HTTP timeout for individual requests. `bw serve` forwards item writes
# to the (possibly self-hosted/remote) Bitwarden server, so a single create can
# take far longer than local work; this ceiling is deliberately generous and is
# overridable via `KP2BW_HTTP_TIMEOUT`. httpx interprets a bare float as the
# *single* timeout applied to connect, read, write, and pool phases together --
# raising it stretches all four, not just the slow-write phase that motivates it.
_HTTP_TIMEOUT_S: float = 180.0

# Sanity ceiling on `KP2BW_HTTP_TIMEOUT`. Above this the value is clamped (with
# a warning) rather than honoured verbatim: a single HTTP request that hangs for
# more than an hour is almost certainly a typo (e.g. `999999`) rather than a
# real tuning need, and a typo here can silently stall a migration for hours.
_HTTP_TIMEOUT_MAX_S: float = 3600.0

# Env var overriding the per-request HTTP timeout, in seconds.
_HTTP_TIMEOUT_ENV: str = "KP2BW_HTTP_TIMEOUT"

# Max length for sanitized CLI output snippets in logs/errors.
_SANITIZED_OUTPUT_MAX_CHARS: int = 240

# bw serve occasionally drops a pooled keepalive connection over a long
# migration (a localhost reset, e.g. WinError 10054). Idempotent requests are
# retried on such a transport error; non-idempotent ones (POST) are not, since a
# reset could hide an item the server already created.
_REQUEST_MAX_ATTEMPTS: int = 3
_REQUEST_RETRY_BACKOFF_S: float = 0.5
_IDEMPOTENT_METHODS: frozenset[str] = frozenset({
    "GET",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
})

# Response-only keys returned by ``GET``/``list`` that must never be sent back in
# a ``PUT`` body: the API expects a create-shaped object (``BwItemCreate``), and
# echoing server-managed fields (notably ``attachments``) risks rejection or
# clobbering state.  The item id travels in the URL, not the body.
_RESPONSE_ONLY_ITEM_KEYS: frozenset[str] = frozenset({
    "object",
    "id",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "attachments",
})

# Bitwarden item type for login entries (1=login, 2=secureNote, 3=card,
# 4=identity).  kp2bw only ever creates/adopts login items, so non-login items
# sharing a name are a user's own data and must never be adopted.
_BW_ITEM_TYPE_LOGIN: int = 1

# Hidden custom-field name kp2bw stamps on every item it creates, carrying the
# source KeePass entry UUID.  This is the *stable identity key*: dedup matches on
# it so two distinct entries that merely share a ``(folder, title)`` never
# collapse onto one item, and re-runs stay idempotent across title/folder edits.
KP2BW_ID_FIELD_NAME: str = "KP2BW_ID"

# Hidden custom-field name carrying a content signature of what kp2bw last wrote
# to the item -- the basis for protecting Bitwarden-side manual edits on re-run.
# A re-run that finds the item's current managed content no longer matching this
# stamp knows a *user* edited it (kp2bw's own writes restamp it), and preserves
# the edit instead of clobbering it.  Excluded from the content diff, like
# KP2BW_ID, so it never makes a re-run look "changed".
KP2BW_SYNC_FIELD_NAME: str = "KP2BW_SYNC"


def item_kp2bw_id(item: BwItemResponse) -> str | None:
    """Return *item*'s KeePass-UUID stamp, or ``None`` if it is unstamped.

    Reads the plain-text ``KP2BW_ID`` custom field written by :mod:`kp2bw.convert`.
    An unstamped item is a legacy import (pre-stable-identity) eligible for a
    one-time ``(folder, name)`` adoption that backfills the stamp.
    """
    for field in item.get("fields") or []:
        if field.get("name") == KP2BW_ID_FIELD_NAME:
            return field.get("value") or None
    return None


def item_kp2bw_sync(item: BwItemResponse) -> str | None:
    """Return *item*'s ``KP2BW_SYNC`` content-signature stamp, or ``None``.

    Absent on legacy items and on anything kp2bw has not written since the
    feature shipped; such items are treated as un-protected (the next write
    establishes the stamp).  See :meth:`Converter._is_user_modified`.
    """
    for field in item.get("fields") or []:
        if field.get("name") == KP2BW_SYNC_FIELD_NAME:
            return field.get("value") or None
    return None


class StripResult(NamedTuple):
    """Outcome of a :meth:`BitwardenServeClient.strip_field_from_items` pass.

    *scanned* is every in-scope item inspected; *stripped* is the subset that
    carried the field and was rewritten.
    """

    scanned: int
    stripped: int


class MigrateResult(NamedTuple):
    """Outcome of a :meth:`BitwardenServeClient.migrate_url_fields_to_uris` pass.

    *scanned* is every in-scope item inspected; *migrated* is the subset that
    carried ``KP2A_URL*`` / ``AndroidApp`` fields and was rewritten to URIs.
    """

    scanned: int
    migrated: int


# Actionable message shown when the Bitwarden CLI cannot be located.
BW_NOT_FOUND_MSG: str = (
    "Bitwarden CLI ('bw') not found on your PATH. Install it and make sure "
    "'bw' is runnable from your shell, then try again. "
    "See https://bitwarden.com/help/cli/ for installation instructions."
)

# Pointer shown when `bw unlock` fails. kp2bw never runs `bw login` itself
# (that is the user's step), so the unlock failure is the earliest point it can
# flag the most common unfixable cause: a self-hosted server older than the
# `bw` CLI. Recent CLIs log in via `/identity/accounts/prelogin/password`, a
# route servers before Vaultwarden 1.36.0 answer with 404, so login never
# succeeds and the subsequent unlock cannot find a session.
BW_LOGIN_COMPAT_HINT: str = (
    "If you cannot log in at all -- e.g. `bw login` returns HTTP 404 on "
    "/identity/accounts/prelogin/password -- your self-hosted server is likely "
    "older than your `bw` CLI."
)

# Deep link to the matching TROUBLESHOOTING.md section (GitHub heading anchor).
TROUBLESHOOTING_LOGIN_404_URL: str = (
    "https://github.com/kjanat/kp2bw/blob/master/TROUBLESHOOTING.md"
    "#login-fails-with-a-404-self-hosted-server-too-old-for-your-bw-cli"
)


def warn_login_compatibility() -> None:
    """Print the login-compat hint to the console as a clickable link.

    Deliberately routed through the shared Rich console rather than ``logger``:
    Rich renders the URL as an OSC 8 hyperlink where the terminal supports it
    and degrades to plain text otherwise, so the clickable form never leaks
    escape codes into the always-on debug log file (which already records the
    bare unlock failure). The URL is both the ``[link]`` target *and* the
    visible text, so a legacy console or a redirected stream still shows the
    address -- only the clickability is lost.
    """
    url = TROUBLESHOOTING_LOGIN_404_URL
    console.print(
        f"[yellow]{escape(BW_LOGIN_COMPAT_HINT)}[/yellow] See [link={url}]{url}[/link]"
    )


def _is_missing_item_error(status_code: int, message: object) -> bool:
    """True when an attachment upload failed because the item wasn't found.

    A freshly created cipher can be momentarily unresolvable by ``bw serve``'s
    attachment endpoint, which looks ``itemid`` up in its local vault cache
    rather than on the server.  Such a failure surfaces as a ``404`` or a
    ``message`` containing "not found", and warrants a sync-and-retry rather
    than being treated as a permanent rejection.
    """
    return status_code == 404 or "not found" in str(message).lower()


def ensure_bw_available() -> None:
    """Verify the ``bw`` CLI is on the PATH.

    Raises :class:`BitwardenClientError` with an actionable message instead of
    letting ``subprocess`` raise a bare ``FileNotFoundError`` (and a long,
    intimidating traceback) when ``bw`` cannot be located.
    """
    if shutil.which("bw") is None:
        raise BitwardenClientError(BW_NOT_FOUND_MSG)


def _find_on_path(filename: str) -> str | None:
    """Return the first PATH directory entry containing *filename*, or ``None``.

    Used for shims (``.ps1``) whose extension is not in ``PATHEXT`` and so are
    invisible to :func:`shutil.which`.
    """
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = ntpath.join(directory, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


def _resolve_bw_command_windows() -> tuple[list[str], str | None]:
    """Resolve the ``bw`` launch command on Windows across all shim flavours.

    Install methods differ in what they put on ``PATH``:

    * native download / scoop / choco → ``bw.exe`` (runnable directly)
    * npm → ``bw.cmd`` **and** ``bw.ps1`` (no ``bw.exe``)

    ``CreateProcess`` (``subprocess`` with ``shell=False``) only runs real
    ``.exe``/``.com`` images, so a ``.cmd``/``.bat`` shim is routed through the
    command processor and a ``.ps1`` shim through PowerShell. Variants are tried
    most-reliable first, so when npm ships both we use ``bw.cmd`` rather than
    paying PowerShell startup. ``.cmd``/``.bat`` is invoked by basename from its
    own directory so an install path with spaces needs no ``cmd`` quoting.
    """
    for name in ("bw.exe", "bw.com"):
        found = shutil.which(name)
        if found:
            return [found], None
    for name in ("bw.cmd", "bw.bat"):
        found = shutil.which(name)
        if found:
            comspec = os.environ.get("COMSPEC", "cmd.exe")
            return [comspec, "/d", "/c", ntpath.basename(found)], ntpath.dirname(found)
    # `.ps1` is not in PATHEXT, so shutil.which can't see it — search manually.
    ps1 = _find_on_path("bw.ps1")
    if ps1:
        powershell = (
            shutil.which("pwsh") or shutil.which("powershell") or "powershell.exe"
        )
        return [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ps1,
        ], None
    raise BitwardenClientError(BW_NOT_FOUND_MSG)


def resolve_bw_command() -> tuple[list[str], str | None]:
    """Resolve how to launch the Bitwarden CLI as a subprocess.

    Returns ``(argv_prefix, cwd)``: *argv_prefix* is prepended to the ``bw``
    arguments for every subprocess call, and *cwd* is the working directory to
    run from (``None`` keeps the caller's cwd).

    On POSIX the resolved ``bw`` is executed directly. On Windows the various
    shim flavours (``bw.exe``, ``bw.cmd``/``bw.bat``, ``bw.ps1``) are resolved
    and wrapped appropriately — see :func:`_resolve_bw_command_windows`.

    Raises :class:`BitwardenClientError` if ``bw`` cannot be found.
    """
    if os.name == "nt":
        return _resolve_bw_command_windows()
    path = shutil.which("bw")
    if path is None:
        raise BitwardenClientError(BW_NOT_FOUND_MSG)
    return [path], None


def parse_listening_pids(netstat_output: str, port: int) -> set[int]:
    """Extract PIDs ``LISTENING`` on ``127.0.0.1:port`` from ``netstat -ano`` output.

    Split out from :func:`_listening_pids` so the (fiddly, column-based) parsing
    is unit-testable without spawning a real listener.  A ``netstat`` row looks
    like ``TCP  127.0.0.1:45707  0.0.0.0:0  LISTENING  1234``.
    """
    needle = f"127.0.0.1:{port}"
    pids: set[int] = set()
    for line in netstat_output.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1] == needle and parts[3] == "LISTENING":
            try:
                pids.add(int(parts[4]))
            except ValueError:
                continue
    return pids


def _listening_pids(port: int) -> set[int]:
    """Return PIDs ``LISTENING`` on ``127.0.0.1:port`` (Windows, via ``netstat``).

    Best-effort: any failure yields an empty set so teardown never raises.
    """
    try:
        result = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return parse_listening_pids(result.stdout, port)


def _kill_port_listeners(port: int) -> None:
    """Force-kill any process still ``LISTENING`` on ``127.0.0.1:port`` (Windows).

    The reliable orphan reaper: regardless of how the ``bw serve`` process tree
    is shaped, or whether the wrapper we tracked already exited, whatever still
    holds the serve port is the orphan to kill.  Best-effort; a kill failure is
    logged, not raised, since this runs during teardown.
    """
    for pid in _listening_pids(port):
        _ = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
        )
        logger.warning(f"Reaped orphaned bw serve process {pid} holding port {port}")


def terminate_serve(
    process: subprocess.Popen[bytes],
    *,
    via_shell: bool = False,
    port: int | None = None,
    timeout: float = 5.0,
) -> None:
    """Stop a running ``bw serve`` together with its descendants.

    On Windows a shim-launched ``bw serve`` runs as a *grandchild* (``cmd.exe``
    wrapper → ``node`` → ``node`` worker, or PowerShell for a ``.ps1``).  Killing
    only the wrapper — or finding it already exited and bailing — orphans the
    worker, which keeps holding the port; and because every ``bw`` invocation
    shares one app-data store, accumulated orphans can deadlock later runs.
    Teardown is therefore belt-and-suspenders: take down the tracked process
    tree, then (Windows) reap anything still ``LISTENING`` on *port*, which
    catches a worker that outlived or re-parented away from its wrapper.
    """
    if process.poll() is None:
        if os.name == "nt":
            if via_shell:
                # terminate() would reach only the cmd.exe wrapper; take the tree.
                _ = subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    check=False,
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                )
                try:
                    _ = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    logger.warning("bw serve did not exit after taskkill /T")
            else:
                process.terminate()
                try:
                    _ = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    logger.warning("bw serve did not exit on SIGTERM, sending SIGKILL")
                    process.kill()
                    try:
                        _ = process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        logger.warning("bw serve did not exit after SIGKILL")
        else:
            # POSIX: bw is commonly a node launcher that spawns a worker; killing
            # only the tracked PID orphans the worker -- it keeps the port and,
            # when kp2bw's stdout is a pipe, holds it open so the parent pipeline
            # never reaches EOF (a multi-minute "still running" hang). bw serve
            # runs in its own session (start_new_session=True), so when the
            # process leads its own group we signal the whole group to take the
            # launcher and worker down together.
            try:
                pgid = os.getpgid(process.pid)
            except ProcessLookupError:
                pgid = None

            def _signal(sig: int) -> None:
                # Group-signal ONLY a real group leader (getpgid == pid, what
                # start_new_session guarantees); otherwise a single-PID kill, so
                # we never signal kp2bw's own group (e.g. a process a caller
                # spawned without its own session).
                if pgid is not None and pgid == process.pid:
                    os.killpg(pgid, sig)
                else:
                    os.kill(process.pid, sig)

            try:
                _signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                _ = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                logger.warning("bw serve did not exit on SIGTERM, sending SIGKILL")
                try:
                    _signal(signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    _ = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    logger.warning("bw serve did not exit after SIGKILL")

    # Windows: reap a shim worker that survived (or re-parented away from) the
    # wrapper we tracked — including the case where the wrapper had already
    # exited, which the old early-return missed, leaving an orphan on the port.
    if os.name == "nt" and port is not None:
        _kill_port_listeners(port)


def sanitize_cli_output(
    output: str,
    *,
    secrets: tuple[str, ...] = (),
    max_chars: int = _SANITIZED_OUTPUT_MAX_CHARS,
) -> str:
    """Normalize and redact CLI output for safe logging/errors."""
    sanitized = " ".join(output.split())
    for secret in secrets:
        if not secret:
            continue
        sanitized = sanitized.replace(secret, "***")
    if len(sanitized) > max_chars:
        return sanitized[:max_chars] + "...[truncated]"
    return sanitized


def format_http_error(resp: httpx.Response) -> str:
    """Extract a human-readable reason from a 4xx/5xx HTTP response.

    ``bw serve`` returns its ``{success, message}`` envelope (and Vaultwarden a
    validation payload) even on error responses, but the body was previously
    discarded -- turning every rejection into an opaque ``HTTP 400`` with no
    cause.  This pulls out ``message``/``validationErrors`` (or the raw text when
    the body is not the expected JSON shape) so the real reason reaches logs and
    errors.  Whitespace-normalised and truncated via :func:`sanitize_cli_output`;
    only the *response* body is read, never request data, so no secret is logged.
    """
    try:
        parsed: Any = resp.json()
    except ValueError:
        text = resp.text
        return sanitize_cli_output(text) if text.strip() else "(empty response body)"
    if isinstance(parsed, dict):
        body: dict[str, Any] = cast(dict[str, Any], parsed)
        message: object = body.get("message")
        details: object = body.get("validationErrors") or body.get("errors")
        parts: list[str] = []
        if message:
            parts.append(str(message))
        if details:
            parts.append(f"details={details}")
        if parts:
            return sanitize_cli_output(" ".join(parts))
    # Parsed but not the expected object envelope (array/scalar): fall back to
    # the raw text rather than re-serialising an unknown-typed value.
    text = resp.text
    return sanitize_cli_output(text) if text.strip() else "(empty response body)"


def send_with_retry(
    send: Callable[[], httpx.Response],
    *,
    method: str,
    path: str,
    idempotent: bool | None = None,
    max_attempts: int = _REQUEST_MAX_ATTEMPTS,
    backoff_s: float = _REQUEST_RETRY_BACKOFF_S,
    sleep: Callable[[float], None] = time.sleep,
) -> httpx.Response:
    """Call *send*, retrying transient transport errors for idempotent requests.

    ``bw serve`` can drop a pooled keepalive connection over a long run; httpx
    surfaces that as :class:`httpx.TransportError` before the request is
    processed, so retrying an idempotent request on a fresh connection recovers
    without risking a duplicate.  Whether a request is idempotent defaults to its
    HTTP method (GET/PUT/DELETE retry, POST does not), but *idempotent* overrides
    that: a ``POST`` that merely replays state (``/sync``, ``/unlock``) passes
    ``idempotent=True`` so a transient reset on startup is retried away rather
    than aborting the run before it begins.  A persistent failure is raised as a
    :class:`BitwardenClientError` so callers see a project error (and per-entry
    handlers can treat it as non-fatal) rather than a raw ``httpx`` traceback
    that aborts the whole migration.  *sleep* is injectable for tests.
    """
    if idempotent is None:
        idempotent = method.upper() in _IDEMPOTENT_METHODS
    attempts = max_attempts if idempotent else 1
    for attempt in range(1, attempts + 1):
        try:
            return send()
        except httpx.TransportError as exc:
            if attempt < attempts:
                logger.warning(
                    f"bw serve {method} {path}: transport error ({exc}); "
                    f"retrying ({attempt}/{attempts - 1})"
                )
                sleep(backoff_s * attempt)
                continue
            raise BitwardenClientError(
                f"bw serve {method} {path} failed after {attempt} attempt(s): {exc}"
            ) from exc
    # The loop always returns or raises above; this satisfies the type checker.
    raise BitwardenClientError(f"bw serve {method} {path}: no attempt was made")


def _find_free_port() -> int:
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _resolve_http_timeout() -> float:
    """Per-request HTTP timeout (seconds), overridable via ``KP2BW_HTTP_TIMEOUT``.

    A slow or self-hosted Bitwarden/Vaultwarden server can make individual item
    writes take far longer than the default, so the env var lets users raise the
    ceiling without code changes. Non-numeric or non-positive values are ignored
    with a warning and the built-in default is used. Values above
    :data:`_HTTP_TIMEOUT_MAX_S` are clamped to that ceiling (with a warning) so a
    typo like ``999999`` can't silently hang a migration for hours.

    The returned float is handed to httpx as a single value, which applies it to
    the *connect*, *read*, *write*, and *pool* phases together -- raising it
    stretches all four, not just the slow-write phase that usually motivates it.
    """
    raw = os.environ.get(_HTTP_TIMEOUT_ENV)
    if not raw:
        return _HTTP_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            f"Ignoring invalid {_HTTP_TIMEOUT_ENV}={raw!r}; "
            f"using default {_HTTP_TIMEOUT_S}s"
        )
        return _HTTP_TIMEOUT_S
    if value <= 0:
        logger.warning(
            f"Ignoring non-positive {_HTTP_TIMEOUT_ENV}={raw!r}; "
            f"using default {_HTTP_TIMEOUT_S}s"
        )
        return _HTTP_TIMEOUT_S
    if value > _HTTP_TIMEOUT_MAX_S:
        logger.warning(
            f"Clamping {_HTTP_TIMEOUT_ENV}={raw!r} to the {_HTTP_TIMEOUT_MAX_S}s "
            f"sanity ceiling; a single request rarely needs longer and a typo "
            f"here can hang the migration for hours"
        )
        return _HTTP_TIMEOUT_MAX_S
    return value


class BitwardenServeClient:
    """Manage a ``bw serve`` process and provide HTTP API access.

    The client starts ``bw serve`` on a random localhost port, waits for it
    to become responsive, unlocks the vault, and synchronises state.  The
    process is terminated cleanly on :meth:`close`, context-manager exit,
    ``atexit``, or ``SIGTERM``/``SIGINT``.
    """

    _process: subprocess.Popen[bytes] | None
    _port: int
    _base_url: str
    _http: httpx.Client
    _http_timeout: float  # per-request timeout shared by sync + async clients
    _previous_sigterm: Callable[[int, FrameType | None], Any] | int | None
    _previous_sigint: Callable[[int, FrameType | None], Any] | int | None
    _folders: dict[str, str]  # name → id cache
    _by_uuid: dict[str, BwItemResponse]  # KP2BW_ID stamp → item (stable identity)
    _legacy_by_folder_name: dict[
        str | None, dict[str, list[BwItemResponse]]
    ]  # unstamped login items: folder → name → [items], for one-time adoption
    _collections: dict[str, str] | None  # name → id cache (None if no org)
    _org_id: str | None
    _collection_id: str | None  # fixed target collection for dedup scoping
    _closed: bool
    _bw_cmd: list[str]  # argv prefix for invoking bw (handles Windows shims)
    _bw_cwd: str | None  # cwd for bw subprocess calls (set for shim invocation)
    _bw_via_shell: bool  # True when bw runs through a cmd.exe wrapper

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __init__(
        self,
        password: str,
        *,
        org_id: str | None = None,
        collection_id: str | None = None,
    ) -> None:
        # Resolve how to launch bw before binding sockets, installing signal
        # handlers, or spawning anything. This fails fast with an actionable
        # message when bw is missing, and transparently wraps Windows .cmd/.bat
        # shims so an npm-installed CLI works rather than crashing later.
        self._bw_cmd, self._bw_cwd = resolve_bw_command()
        self._bw_via_shell = len(self._bw_cmd) > 1

        self._port = _find_free_port()
        self._base_url = f"http://127.0.0.1:{self._port}"
        self._process = None
        self._closed = False
        self._http_timeout = _resolve_http_timeout()
        self._http = httpx.Client(
            base_url=self._base_url,
            timeout=self._http_timeout,
        )
        self._org_id = org_id
        self._collection_id = collection_id

        self._folders = {}
        self._by_uuid = {}
        self._legacy_by_folder_name = {}
        self._collections = None

        # Register cleanup handlers early so close() is safe to call at
        # any point during init (e.g. if _wait_for_ready times out).
        self._previous_sigterm = signal.getsignal(signal.SIGTERM)
        self._previous_sigint = signal.getsignal(signal.SIGINT)
        atexit.register(self.close)
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        session = self._get_session(password)
        self._start_serve(session)
        self._wait_for_ready()
        self._unlock(password)
        self._sync()

        # Populate folder cache and dedup indexes from existing vault state.
        self._folders = self.list_folders()
        self._build_dedup_index()

        # Load existing org collections if an org ID was provided.
        if self._org_id:
            self._collections = self.list_collections()

    # -- Context manager -----------------------------------------------

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- Start / stop --------------------------------------------------

    def _get_session(self, password: str) -> str | None:
        """Unlock the vault via ``bw unlock --raw`` and return the session key."""
        logger.log(VERBOSE, "Obtaining session key via bw unlock --raw")
        try:
            result = subprocess.run(
                [*self._bw_cmd, "unlock", "--raw", "--passwordenv", "_KP2BW_BW_PW"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                stdin=subprocess.DEVNULL,
                cwd=self._bw_cwd,
                env={**os.environ, "_KP2BW_BW_PW": password},
            )
        except FileNotFoundError as exc:
            # The resolved command (bw, or cmd.exe for a shim) could not be
            # executed — surface the actionable message, not a raw traceback.
            raise BitwardenClientError(BW_NOT_FOUND_MSG) from exc
        except subprocess.TimeoutExpired:
            logger.warning("bw unlock timed out while obtaining session key")
            return None
        if result.returncode != 0:
            stderr_text = sanitize_cli_output(result.stderr, secrets=(password,))
            message = (
                f"bw unlock exited with code {result.returncode}; "
                f"bw serve will start without BW_SESSION"
            )
            if stderr_text:
                message += f"; stderr: {stderr_text}"
            logger.warning(message)
            warn_login_compatibility()
            return None
        session = result.stdout.strip()
        if session:
            logger.log(VERBOSE, "Obtained session key via bw unlock")
        else:
            logger.warning("bw unlock returned empty session key")
        return session or None

    def _start_serve(self, session: str | None = None) -> None:
        """Spawn ``bw serve --port <port> --hostname localhost``.

        Always passes an explicit *env* dict so a stale ``BW_SESSION`` in
        the parent process environment is never leaked to the child.
        """
        cmd = [
            *self._bw_cmd,
            "serve",
            "--port",
            str(self._port),
            "--hostname",
            "127.0.0.1",
        ]
        env = {**os.environ}
        if session:
            env["BW_SESSION"] = session
        else:
            env.pop("BW_SESSION", None)
        logger.log(
            VERBOSE,
            f"Starting bw serve on port {self._port} "
            f"(BW_SESSION={'set' if session else 'not set'})",
        )
        try:
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=self._bw_cwd,
                env=env,
                # POSIX: run bw serve in its own session/process group so teardown
                # can kill the launcher *and* its node worker together (see
                # terminate_serve). Without this an orphaned worker keeps the port
                # and, when our stdout is a pipe, holds it open -> the parent
                # pipeline hangs. Ignored on Windows (taskkill /T handles the tree).
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise BitwardenClientError(BW_NOT_FOUND_MSG) from exc

    def _wait_for_ready(self) -> None:
        """Poll ``GET /status`` until the server is responsive."""
        start = time.monotonic()
        deadline = start + _SERVE_STARTUP_TIMEOUT_S
        while time.monotonic() < deadline:
            # Check the process hasn't died.
            if self._process is not None and self._process.poll() is not None:
                stderr_text = ""
                if self._process.stderr is not None:
                    stderr_text = sanitize_cli_output(
                        self._process.stderr.read().decode("utf-8", errors="replace")
                    )
                message = (
                    f"bw serve exited unexpectedly with code {self._process.returncode}"
                )
                if stderr_text:
                    message += f"; stderr: {stderr_text}"
                raise BitwardenClientError(message)
            try:
                resp = self._http.get("/status")
                if resp.status_code == 200:
                    elapsed = time.monotonic() - start
                    logger.log(VERBOSE, f"bw serve is ready ({elapsed:.1f}s)")
                    return
            except httpx.ConnectError:
                pass
            time.sleep(_SERVE_POLL_INTERVAL_S)

        self.close()
        raise BitwardenClientError(
            f"bw serve did not become ready within {_SERVE_STARTUP_TIMEOUT_S}s"
        )

    def close(self) -> None:
        """Terminate the ``bw serve`` process and release resources."""
        if self._closed:
            return
        self._closed = True

        # Unregister atexit to avoid double-close.
        atexit.unregister(self.close)

        # Restore previous signal handlers (getsignal can return None for
        # handlers installed from C code; signal.signal rejects None).
        if self._previous_sigterm is not None:
            signal.signal(signal.SIGTERM, self._previous_sigterm)
        if self._previous_sigint is not None:
            signal.signal(signal.SIGINT, self._previous_sigint)

        # Call teardown unconditionally (not gated on poll()): on Windows the
        # tracked wrapper can exit while its node worker lives on, so the
        # port-based reap inside terminate_serve must run even then.
        if self._process is not None:
            logger.log(VERBOSE, "Terminating bw serve process")
            terminate_serve(
                self._process, via_shell=self._bw_via_shell, port=self._port
            )

        self._process = None
        try:
            self._http.close()
        except Exception:
            logger.debug("Ignoring error while closing HTTP client", exc_info=True)

    def _signal_handler(self, signum: int, _frame: FrameType | None) -> None:
        """Handle SIGTERM/SIGINT by cleaning up, then re-raising."""
        self.close()
        # Re-raise so the caller sees the expected signal behaviour.
        previous = (
            self._previous_sigterm
            if signum == signal.SIGTERM
            else self._previous_sigint
        )
        if previous == signal.SIG_IGN:
            # Respect ignored signal handlers.
            return
        if previous == signal.SIG_DFL or previous is None:
            # Default handler / None — just exit.
            raise SystemExit(128 + signum)
        if isinstance(previous, int):
            raise SystemExit(128 + signum)
        previous(signum, _frame)

    # ------------------------------------------------------------------
    # Core HTTP helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: dict[str, str] | None = None,
        idempotent: bool | None = None,
    ) -> dict[str, Any]:
        """Send an HTTP request and return the parsed ``data`` payload.

        Raises :class:`BitwardenClientError` on non-success responses or
        when the ``bw serve`` JSON envelope reports ``success: false``.

        *idempotent* overrides method-based retry classification for a ``POST``
        that merely replays state (``/sync``, ``/unlock``); see
        :func:`send_with_retry`.
        """
        resp = send_with_retry(
            lambda: self._http.request(method, path, json=json_body, params=params),
            method=method,
            path=path,
            idempotent=idempotent,
        )
        if resp.status_code >= 400:
            raise BitwardenClientError(
                f"bw serve returned HTTP {resp.status_code} for {method} {path}: "
                f"{format_http_error(resp)}"
            )

        try:
            body: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise BitwardenClientError(
                f"bw serve returned non-JSON response "
                f"(HTTP {resp.status_code}) for {method} {path}"
            ) from exc

        if not body.get("success", False):
            msg = body.get("message", "unknown error")
            raise BitwardenClientError(f"bw serve error on {method} {path}: {msg}")

        return body.get("data", {})

    # ------------------------------------------------------------------
    # Vault operations (lifecycle)
    # ------------------------------------------------------------------

    def _unlock(self, password: str) -> None:
        """Unlock the vault via ``POST /unlock``.

        Replaying an unlock is harmless, so it is retried on a transient reset.
        """
        logger.log(VERBOSE, "Unlocking vault via bw serve")
        self._request(
            "POST", "/unlock", json_body={"password": password}, idempotent=True
        )

    def _sync(self) -> None:
        """Synchronise vault state via ``POST /sync``.

        Replaying a sync is harmless, so it is retried on a transient reset.
        """
        logger.log(VERBOSE, "Syncing vault via bw serve")
        self._request("POST", "/sync", idempotent=True)

    def sync(self) -> None:
        """Force a vault sync (public API)."""
        self._sync()

    # ------------------------------------------------------------------
    # CRUD — folders
    # ------------------------------------------------------------------

    def list_folders(self) -> dict[str, str]:
        """Return ``{name: id}`` mapping of all vault folders."""
        data = self._request("GET", "/list/object/folders")
        folders: list[BwFolder] = data.get("data", [])
        return {f["name"]: f["id"] for f in folders}

    def create_folder(self, name: str) -> str:
        """Create a folder and return its server-assigned ID.

        Returns the cached ID if a folder with this name already exists.
        """
        existing = self._folders.get(name)
        if existing is not None:
            return existing

        data = self._request("POST", "/object/folder", json_body={"name": name})
        folder_id: str = data["id"]
        self._folders[name] = folder_id
        logger.log(VERBOSE, f"Created folder {name!r} → {folder_id}")
        return folder_id

    def has_folder(self, name: str) -> bool:
        """Check whether a folder with the given name exists."""
        return name in self._folders

    # ------------------------------------------------------------------
    # CRUD — items
    # ------------------------------------------------------------------

    def list_items(
        self,
        *,
        folder_id: str | None = None,
        organization_id: str | None = None,
        collection_id: str | None = None,
    ) -> list[BwItemResponse]:
        """Return vault items, optionally filtered by folder, organization, or collection."""
        params: dict[str, str] = {}
        if folder_id is not None:
            params["folderid"] = folder_id
        if organization_id is not None:
            params["organizationId"] = organization_id
        if collection_id is not None:
            params["collectionId"] = collection_id
        data = self._request("GET", "/list/object/items", params=params or None)
        items: list[BwItemResponse] = data.get("data", [])
        return items

    def create_item(self, item: BwItemCreate) -> str:
        """Create a single vault item via HTTP and return its ID."""
        data = self._request("POST", "/object/item", json_body=item)
        item_id: str = data["id"]
        logger.log(VERBOSE, f"Created item {item.get('name', '?')!r} → {item_id}")
        return item_id

    def get_item(self, item_id: str) -> BwItemResponse:
        """Fetch a single full item (including ``attachments``) via ``GET``.

        The list endpoint is enough for content dedup, but its ``attachments``
        array is only consulted for upload-if-missing reconciliation, so this
        authoritative fetch is used to avoid creating duplicate attachments.
        """
        data = self._request("GET", f"/object/item/{item_id}")
        return cast(BwItemResponse, data)

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        """Replace an existing vault item via ``PUT /object/item/{id}``.

        The API requires the full object in the request body — partial updates
        are not supported.  Callers may pass an item read back from the vault
        (a ``BwItemResponse``); response-only keys (``id``, ``object``,
        ``revisionDate``, ``attachments``, …) are stripped here so the wire body
        is the create-shaped object the endpoint expects.  Stripping happens on a
        copy, so a caller can still hand the original (id-bearing) object to
        :meth:`update_dedup_entry`.
        """
        body: dict[str, Any] = {
            k: v
            for k, v in cast(dict[str, Any], item).items()
            if k not in _RESPONSE_ONLY_ITEM_KEYS
        }
        self._request("PUT", f"/object/item/{item_id}", json_body=body)
        logger.log(VERBOSE, f"Updated item {item.get('name', '?')!r} ({item_id})")

    def strip_field_from_items(self, *field_names: str) -> StripResult:
        """Remove the named custom field(s) from every in-scope item carrying any.

        The finalize step for users adopting Bitwarden: drops kp2bw's managed
        stamps (``KP2BW_ID`` dedup key and the ``KP2BW_SYNC`` edit-protection
        signature) once a migration is trusted, leaving clean items behind.
        Scope mirrors a migration -- the configured organisation/collection when
        set, otherwise the personal vault -- so only items kp2bw could have
        stamped are touched.  An item carrying none of *field_names* is skipped;
        each match is rewritten once via a full :meth:`update_item` ``PUT`` that
        drops every named field present.  Returns the scanned/stripped counts.

        The strip itself is re-runnable (a second pass finds nothing), but it is
        **irreversible** and degrades future migrations: the stamp is the stable
        identity key, and without it a re-run falls back to ``(folder, name)``
        matching -- the very collision the stamp exists to disambiguate -- so
        entries sharing a folder and title can then be duplicated or mismatched.
        It is therefore a deliberate final step, gated by a confirmation in the
        CLI (skippable with ``-y`` for callers who know what they want).
        """
        targets = frozenset(field_names)
        items = self.list_items(
            organization_id=self._org_id,
            collection_id=self._collection_id,
        )
        stripped = 0
        for item in items:
            fields = item.get("fields") or []
            if not any(field.get("name") in targets for field in fields):
                continue
            item["fields"] = [
                field for field in fields if field.get("name") not in targets
            ]
            self.update_item(item["id"], item)
            stripped += 1
        logger.info(
            f"Stripped {', '.join(field_names)} from {stripped} of "
            f"{len(items)} scanned items"
        )
        return StripResult(scanned=len(items), stripped=stripped)

    def migrate_url_fields_to_uris(
        self, *, plain_match: UriMatchValue, interpret_syntax: bool
    ) -> MigrateResult:
        """Re-fold legacy ``KP2A_URL*`` / ``AndroidApp`` custom fields into URIs.

        The Bitwarden-only upgrade pass for users who imported before URL folding
        and do not want to re-import: each in-scope login item carrying those
        fields is rewritten so they become login URIs (appended to existing ones,
        de-duplicated) and the redundant fields are dropped.  Scope mirrors a
        migration (the configured org/collection, else the personal vault). Items
        without such fields are left untouched; only changed items are PUT.
        Safe to repeat -- a second pass finds nothing left to migrate.
        """
        items = self.list_items(
            organization_id=self._org_id,
            collection_id=self._collection_id,
        )
        migrated = 0
        for item in items:
            if item.get("type") != _BW_ITEM_TYPE_LOGIN:
                continue
            login = item.get("login")
            if login is None:
                continue
            new_fields, new_uris, changed = remap_item_fields_to_uris(
                item.get("fields") or [],
                login.get("uris") or [],
                plain_match=plain_match,
                interpret_syntax=interpret_syntax,
            )
            if not changed:
                continue
            item["fields"] = new_fields
            login["uris"] = new_uris
            item["login"] = login
            self.update_item(item["id"], item)
            migrated += 1
        logger.info(
            f"Migrated URL fields to URIs on {migrated} of {len(items)} scanned items"
        )
        return MigrateResult(scanned=len(items), migrated=migrated)

    def create_items_batch(
        self,
        entries: Mapping[str, tuple[str | None, BwItemCreate]],
        *,
        on_item_created: Callable[[], None] | None = None,
        on_item_failed: Callable[[str, BitwardenClientError], None] | None = None,
        create_folders: bool = True,
    ) -> dict[str, str]:
        """Create folders and items via HTTP, returning ``{key: item_id}``.

        *entries* maps arbitrary keys to ``(folder_name, bw_item_dict)`` tuples.
        Folders are created/resolved first, then items are created sequentially
        with the correct ``folderId`` bound.  When *create_folders* is ``False``,
        folder creation and ``folderId`` binding are skipped, leaving items in
        the personal-vault root while any collection IDs on the items still
        apply.

        A single create that fails (``bw serve`` drops or times out the request,
        surfaced as :class:`BitwardenClientError`) is non-fatal: the item is
        skipped and reported via *on_item_failed*, and the remaining entries are
        still migrated rather than stranded -- the same robustness the update and
        attachment phases have (issue #24).  A folder whose creation fails skips
        its items, which are reported failed rather than silently created in the
        no-folder root.  Re-running is safe: stable-UUID dedup adopts anything a
        timed-out request actually created server-side.

        *on_item_created* is called after each successful item creation and
        *on_item_failed* after each skipped one; callers use them to advance a
        progress bar and tally outcomes without depending on the UI library.
        """
        # Ensure all required folders exist. A folder whose creation fails is
        # recorded so its items are skipped, not misplaced into the no-folder root.
        folder_names: set[str] = (
            {fname for fname, _ in entries.values() if fname}
            if create_folders
            else set()
        )
        failed_folders: set[str] = set()
        for fname in sorted(folder_names):
            try:
                self.create_folder(fname)
            except BitwardenClientError as exc:
                logger.warning(
                    f"Could not create folder {fname!r}; its items are skipped "
                    f"this run (a re-run is safe): {exc}"
                )
                failed_folders.add(fname)

        key_to_id: dict[str, str] = {}
        for key, (folder_name, bw_item) in entries.items():
            name = bw_item.get("name", "?")
            if folder_name is not None and folder_name in failed_folders:
                if on_item_failed is not None:
                    on_item_failed(
                        key,
                        BitwardenClientError(
                            f"folder {folder_name!r} could not be created"
                        ),
                    )
                continue
            # Bind folder ID — shallow-copy rather than mutating the shared dict.
            item = copy.copy(bw_item)
            item["folderId"] = (
                self._folders.get(folder_name)
                if create_folders and folder_name
                else None
            )
            try:
                item_id = self.create_item(item)
            except BitwardenClientError as exc:
                # One bad entry must not abort the run and strand every entry
                # after it; a re-run adopts it if the server created it anyway.
                logger.warning(
                    f"Could not create item {name!r}; skipping it this run "
                    f"(a re-run is safe): {exc}"
                )
                if on_item_failed is not None:
                    on_item_failed(key, exc)
                continue
            key_to_id[key] = item_id
            if on_item_created is not None:
                on_item_created()

        return key_to_id

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _build_dedup_index(self) -> None:
        """Build the stable-identity dedup indexes from existing vault state.

        Populates two structures:

        * :attr:`_by_uuid` — ``{KP2BW_ID stamp: item}`` for every item kp2bw has
          already stamped.  This is the authoritative identity map: a KeePass
          entry is matched to its Bitwarden item by UUID, so distinct entries
          sharing a ``(folder, title)`` never collapse and re-runs are idempotent.
        * :attr:`_legacy_by_folder_name` — ``{folder: {name: [items]}}`` of
          *unstamped login* items (legacy imports made before stable identity).
          A KeePass entry with no UUID match claims one of these by
          ``(folder, name)`` and backfills the stamp — a one-time adoption that
          avoids re-creating the whole vault on the first post-upgrade run.

        Items are stored in full so callers can inspect ``collectionIds`` and
        call :meth:`update_item` without an extra GET.  Scoping (most-specific
        filter wins) is unchanged from the previous ``(folder, name)`` index:

        * **Fixed collection** (``collection_id`` set): only items already in
          that collection are indexed.
        * **Org-only** (``org_id`` set, no ``collection_id``): items belonging
          to the organisation; personal entries don't shadow an empty org vault.
        * **Personal vault** (both ``None``): all visible items.

        Non-login items are excluded from the legacy index: kp2bw only ever
        creates login items, so a non-login item sharing a name is a user's own
        item and must never be adopted or mutated.
        """
        id_to_name: dict[str, str] = {
            fid: fname for fname, fid in self._folders.items()
        }
        by_uuid: dict[str, BwItemResponse] = {}
        legacy: dict[str | None, dict[str, list[BwItemResponse]]] = {}
        for item in self.list_items(
            organization_id=self._org_id,
            collection_id=self._collection_id,
        ):
            kp_uuid = item_kp2bw_id(item)
            if kp_uuid:
                by_uuid[kp_uuid] = item
                continue
            # Unstamped legacy item — index for one-time (folder, name) adoption,
            # but only login items (kp2bw never touches a user's other items).
            if item.get("type") != _BW_ITEM_TYPE_LOGIN:
                continue
            name: str = item.get("name", "")
            if not name:
                continue
            folder_id: str | None = item.get("folderId") or None
            folder_name = id_to_name.get(folder_id) if folder_id else None
            legacy.setdefault(folder_name, {}).setdefault(name, []).append(item)
        self._by_uuid = by_uuid
        self._legacy_by_folder_name = legacy

    def get_item_by_uuid(self, kp_uuid: str) -> BwItemResponse | None:
        """Return the item stamped with *kp_uuid*, or ``None`` (stable identity)."""
        return self._by_uuid.get(kp_uuid)

    def claim_legacy_item(self, folder: str | None, name: str) -> BwItemResponse | None:
        """Claim one unstamped legacy item matching ``(folder, name)``, or ``None``.

        Pops the item so a second KeePass entry sharing the ``(folder, name)``
        cannot claim it too — that sibling falls through to creation instead,
        recovering an item the old ``(folder, title)`` dedup would have collapsed.
        The caller backfills the ``KP2BW_ID`` stamp onto the claimed item.
        """
        bucket = self._legacy_by_folder_name.get(folder, {}).get(name)
        if not bucket:
            return None
        return bucket.pop()

    def refresh_dedup_index(self) -> None:
        """Re-query the vault and rebuild the dedup indexes."""
        self._folders = self.list_folders()
        self._build_dedup_index()

    def update_dedup_entry(self, kp_uuid: str, item: BwItemResponse) -> None:
        """Refresh the cached item for *kp_uuid* after an in-place update.

        Keeps :attr:`_by_uuid` current after :meth:`update_item` so a later
        lookup of the same stamp returns fresh data.  Each KeePass entry has a
        unique UUID and is processed once per run, so this is defensive — it
        matters only if a future flow revisits a stamp within a single run.
        """
        self._by_uuid[kp_uuid] = item

    # ------------------------------------------------------------------
    # CRUD — org collections
    # ------------------------------------------------------------------

    def list_collections(self) -> dict[str, str]:
        """Return ``{name: id}`` mapping of org collections."""
        if not self._org_id:
            return {}
        data = self._request(
            "GET",
            "/list/object/org-collections",
            params={"organizationId": self._org_id},
        )
        colls: list[BwCollection] = data.get("data", [])
        return {c["name"]: c["id"] for c in colls}

    def create_org_collection(self, name: str) -> str | None:
        """Create an org collection and return its ID. Cached."""
        if not name:
            return None
        if not self._org_id:
            return None

        if self._collections is None:
            self._collections = {}

        existing = self._collections.get(name)
        if existing is not None:
            return existing

        data = self._request(
            "POST",
            "/object/org-collection",
            json_body={
                "organizationId": self._org_id,
                "name": name,
                "groups": [],
            },
        )
        coll_id: str = data["id"]
        self._collections[name] = coll_id
        logger.log(VERBOSE, f"Created org collection {name!r} → {coll_id}")
        return coll_id

    # ------------------------------------------------------------------
    # CRUD — attachments
    # ------------------------------------------------------------------

    def get_attachment(self, item_id: str, attachment_id: str) -> bytes:
        """Download one attachment's decrypted bytes via ``GET /object/attachment``.

        Unlike the JSON endpoints this returns the raw file body
        (octet-stream), so it bypasses the :meth:`_request` envelope handling.
        Used by content-aware reconciliation to compare a vault attachment
        against the KeePass-derived bytes before deciding whether to refresh it.
        """
        resp = self._http.get(
            f"/object/attachment/{attachment_id}",
            params={"itemid": item_id},
        )
        if resp.status_code >= 400:
            raise BitwardenClientError(
                f"bw serve returned HTTP {resp.status_code} downloading "
                f"attachment {attachment_id} on item {item_id}"
            )
        return resp.content

    def delete_attachment(self, item_id: str, attachment_id: str) -> None:
        """Delete one attachment via ``DELETE /object/attachment/{id}``.

        Used after a content-changed attachment is re-uploaded so the stale
        copy is removed (upload-then-delete keeps the file safe if the upload
        fails).
        """
        self._request(
            "DELETE",
            f"/object/attachment/{attachment_id}",
            params={"itemid": item_id},
        )
        logger.log(VERBOSE, f"Deleted attachment {attachment_id} from item {item_id}")

    # ------------------------------------------------------------------
    # Async attachment uploads
    # ------------------------------------------------------------------

    async def upload_attachment(
        self,
        client: httpx.AsyncClient,
        item_id: str,
        filename: str,
        data: bytes,
    ) -> None:
        """Upload one attachment via multipart ``POST /attachment``.

        A just-created item can be momentarily unresolvable by ``bw serve``'s
        attachment endpoint, which resolves ``itemid`` from its local vault
        cache rather than from the server.  On such a not-found failure, force a
        vault sync (so freshly created IDs become visible) and retry once before
        treating the upload as failed.
        """
        for attempt in range(2):
            resp = await client.post(
                "/attachment",
                params={"itemid": item_id},
                files={"file": (filename, data)},
            )
            try:
                parsed: Any = resp.json()
            except ValueError:
                parsed = None
            # Guard against a non-object JSON body (array/string) so reading the
            # envelope can't raise AttributeError instead of a clean error.
            body: dict[str, Any] = (
                cast(dict[str, Any], parsed) if isinstance(parsed, dict) else {}
            )

            if resp.status_code < 400 and body.get("success", False):
                logger.log(
                    VERBOSE, f"Uploaded attachment {filename!r} to item {item_id}"
                )
                return

            # bw serve reports command-level failures (e.g. "Premium status is
            # required", storage-quota or attachment-size limits) as HTTP 400
            # with the real reason in the body's ``message`` field.  Surface it
            # instead of an opaque status code so the user knows *why* a file
            # was rejected.
            message = body.get("message")
            if not message:
                message = f"HTTP {resp.status_code}"
                if parsed is None:
                    message += " (non-JSON response)"

            # A freshly created item may not yet be in bw serve's local cache;
            # sync once so its ID resolves, then retry the upload.
            if attempt == 0 and _is_missing_item_error(resp.status_code, message):
                logger.log(
                    VERBOSE,
                    f"Item {item_id} not yet resolvable for attachment "
                    f"{filename!r}; syncing vault and retrying",
                )
                await client.post("/sync")
                continue

            raise BitwardenClientError(
                f"Attachment upload failed for {filename!r} on item {item_id}: "
                f"{message}"
            )

    async def upload_attachments_parallel(
        self,
        items: list[tuple[str, list[tuple[str, bytes]]]],
        *,
        max_concurrency: int = 4,
    ) -> list[tuple[str, str]]:
        """Upload all attachments with bounded parallelism.

        *items* is a list of ``(item_id, [(filename, data), ...])`` tuples.

        Returns the ``(item_id, filename)`` pairs of any uploads that failed
        (empty list when all succeed).  The structured pairs let the caller
        pair a successful upload with the stale copy it replaces (so a
        content-changed attachment is only deleted once its replacement
        landed).  Failures are **non-fatal**: a single rejected file must not
        abort the whole migration and discard every other entry's progress.
        """
        total = sum(len(atts) for _, atts in items)
        if total == 0:
            return []

        logger.info(f"Uploading {total} attachments (concurrency={max_concurrency})")
        sem = asyncio.Semaphore(max_concurrency)

        async def _upload_one(
            client: httpx.AsyncClient,
            item_id: str,
            filename: str,
            data: bytes,
        ) -> None:
            async with sem:
                await self.upload_attachment(client, item_id, filename, data)

        async with httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._http_timeout,
        ) as client:
            tasks: list[asyncio.Task[None]] = []
            keys: list[tuple[str, str]] = []
            for item_id, attachments in items:
                for filename, data in attachments:
                    tasks.append(
                        asyncio.create_task(
                            _upload_one(client, item_id, filename, data)
                        )
                    )
                    keys.append((item_id, filename))
            results = await asyncio.gather(*tasks, return_exceptions=True)

        failed: list[tuple[str, str]] = []
        for (item_id, filename), result in zip(keys, results, strict=True):
            if isinstance(result, BaseException):
                logger.error(
                    f"Attachment upload failed for {filename!r} (item {item_id}): "
                    f"{result}"
                )
                failed.append((item_id, filename))

        succeeded = total - len(failed)
        if failed:
            logger.warning(
                f"{len(failed)}/{total} attachment upload(s) failed; "
                f"continuing with the remaining entries"
            )
        logger.info(f"Uploaded {succeeded}/{total} attachments")
        return failed

    def upload_attachments(
        self,
        items: list[tuple[str, list[tuple[str, bytes]]]],
        *,
        max_concurrency: int = 4,
    ) -> list[tuple[str, str]]:
        """Synchronous wrapper for :meth:`upload_attachments_parallel`.

        Returns the ``(item_id, filename)`` pairs of failed uploads (empty when
        all succeed); failures are non-fatal so the migration completes and the
        caller can summarise and skip any dependent stale-copy deletes.
        """
        return asyncio.run(
            self.upload_attachments_parallel(items, max_concurrency=max_concurrency)
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def port(self) -> int:
        """The port ``bw serve`` is listening on."""
        return self._port

    @property
    def base_url(self) -> str:
        """Base URL of the running ``bw serve`` instance."""
        return self._base_url

    @property
    def org_id(self) -> str | None:
        """Organisation ID, if provided."""
        return self._org_id

    @property
    def folders(self) -> dict[str, str]:
        """Cached ``{name: id}`` folder mapping."""
        return self._folders
