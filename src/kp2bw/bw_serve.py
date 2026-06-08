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
from typing import Any, Self, cast

import httpx

from . import VERBOSE
from .bw_types import BwCollection, BwFolder, BwItemCreate, BwItemResponse
from .exceptions import BitwardenClientError

logger = logging.getLogger(__name__)

# How long to wait for `bw serve` to become responsive.
_SERVE_STARTUP_TIMEOUT_S: float = 60.0

# Polling interval when waiting for serve to start.
_SERVE_POLL_INTERVAL_S: float = 0.25

# Default HTTP timeout for individual requests.
_HTTP_TIMEOUT_S: float = 60.0

# Max length for sanitized CLI output snippets in logs/errors.
_SANITIZED_OUTPUT_MAX_CHARS: int = 240

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

# Actionable message shown when the Bitwarden CLI cannot be located.
BW_NOT_FOUND_MSG: str = (
    "Bitwarden CLI ('bw') not found on your PATH. Install it and make sure "
    "'bw' is runnable from your shell, then try again. "
    "See https://bitwarden.com/help/cli/ for installation instructions."
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


def terminate_serve(
    process: subprocess.Popen[bytes],
    *,
    via_shell: bool = False,
    timeout: float = 5.0,
) -> None:
    """Stop a running ``bw serve`` process together with its descendants.

    When ``bw`` is launched through a Windows shim wrapper (``cmd.exe`` for a
    ``bw.cmd``/``bw.bat``, or PowerShell for a ``bw.ps1``),
    :meth:`subprocess.Popen.terminate` reaches only the wrapper and orphans the
    real ``bw serve``, which keeps holding the port. In that case the whole
    process tree is killed with ``taskkill /F /T`` instead.
    """
    if process.poll() is not None:
        return
    if via_shell and os.name == "nt":
        # terminate() would only kill the cmd.exe wrapper; take down the tree.
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
        return
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


def _find_free_port() -> int:
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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
    _previous_sigterm: Callable[[int, FrameType | None], Any] | int | None
    _previous_sigint: Callable[[int, FrameType | None], Any] | int | None
    _folders: dict[str, str]  # name → id cache
    _existing_entries: dict[
        str | None, dict[str, BwItemResponse]
    ]  # folder_name → {name → item}
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
        self._http = httpx.Client(
            base_url=self._base_url,
            timeout=_HTTP_TIMEOUT_S,
        )
        self._org_id = org_id
        self._collection_id = collection_id

        self._folders = {}
        self._existing_entries = {}
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

        # Populate folder cache and dedup index from existing vault state.
        self._folders = self.list_folders()
        self._existing_entries = self._build_dedup_index()

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

        if self._process is not None and self._process.poll() is None:
            logger.log(VERBOSE, "Terminating bw serve process")
            terminate_serve(self._process, via_shell=self._bw_via_shell)

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
    ) -> dict[str, Any]:
        """Send an HTTP request and return the parsed ``data`` payload.

        Raises :class:`BitwardenClientError` on non-success responses or
        when the ``bw serve`` JSON envelope reports ``success: false``.
        """
        resp = self._http.request(
            method,
            path,
            json=json_body,
            params=params,
        )
        if resp.status_code >= 400:
            raise BitwardenClientError(
                f"bw serve returned HTTP {resp.status_code} for {method} {path}"
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
        """Unlock the vault via ``POST /unlock``."""
        logger.log(VERBOSE, "Unlocking vault via bw serve")
        self._request("POST", "/unlock", json_body={"password": password})

    def _sync(self) -> None:
        """Synchronise vault state via ``POST /sync``."""
        logger.log(VERBOSE, "Syncing vault via bw serve")
        self._request("POST", "/sync")

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

    def create_items_batch(
        self,
        entries: dict[str, tuple[str | None, BwItemCreate]],
        *,
        on_item_created: Callable[[], None] | None = None,
    ) -> dict[str, str]:
        """Create folders and items via HTTP, returning ``{key: item_id}``.

        *entries* maps arbitrary keys to ``(folder_name, bw_item_dict)`` tuples.
        Folders are created/resolved first, then items are created sequentially
        with the correct ``folderId`` bound.

        *on_item_created* is called after each successful item creation; callers
        use it to advance a progress bar without creating a direct dependency on
        the UI library.
        """
        # Ensure all required folders exist.
        folder_names = {fname for fname, _ in entries.values() if fname}
        for fname in sorted(folder_names):
            self.create_folder(fname)

        key_to_id: dict[str, str] = {}
        for key, (folder_name, bw_item) in entries.items():
            # Bind folder ID — shallow-copy rather than mutating the shared dict.
            item = copy.copy(bw_item)
            item["folderId"] = self._folders.get(folder_name) if folder_name else None
            item_id = self.create_item(item)
            key_to_id[key] = item_id
            if on_item_created is not None:
                on_item_created()

        return key_to_id

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _build_dedup_index(self) -> dict[str | None, dict[str, BwItemResponse]]:
        """Build a ``{folder_name: {item_name: item}}`` index for O(1) dedup.

        Stores the full item response so callers can inspect ``collectionIds``
        and call :meth:`update_item` without an extra GET.

        Scoping rules (most-specific filter wins):

        * **Fixed collection** (``collection_id`` set): only items already in
          that collection are indexed.  Items in other collections are treated
          as new, so they are created — not silently skipped — when the user
          imports into a specific target collection.
        * **Org-only** (``org_id`` set, no ``collection_id``): items belonging
          to the organisation are indexed.  Personal-vault entries don't shadow
          an empty org vault.  Collection membership of existing items can be
          updated via :meth:`update_item` (collection-aware dedup).
        * **Personal vault** (both ``None``): all visible items are indexed.
          Org-shared items visible to the user may produce false positives
          (pre-existing limitation, intentionally asymmetric).
        """
        id_to_name: dict[str, str] = {
            fid: fname for fname, fid in self._folders.items()
        }
        index: dict[str | None, dict[str, BwItemResponse]] = {}
        for item in self.list_items(
            organization_id=self._org_id,
            collection_id=self._collection_id,
        ):
            folder_id: str | None = item.get("folderId") or None
            folder_name = id_to_name.get(folder_id) if folder_id else None
            name: str = item.get("name", "")
            if not name:
                continue
            index.setdefault(folder_name, {})[name] = item
        return index

    def entry_exists(self, folder: str | None, name: str) -> bool:
        """Check whether an entry with *name* already exists in *folder*."""
        return name in self._existing_entries.get(folder, {})

    def get_existing_item(self, folder: str | None, name: str) -> BwItemResponse | None:
        """Return the cached item response for *name* in *folder*, or ``None``."""
        return self._existing_entries.get(folder, {}).get(name)

    def refresh_dedup_index(self) -> None:
        """Re-query the vault and rebuild the dedup index."""
        self._folders = self.list_folders()
        self._existing_entries = self._build_dedup_index()

    def update_dedup_entry(
        self, folder: str | None, name: str, item: BwItemResponse
    ) -> None:
        """Update a single cached entry after an in-place :meth:`update_item` call.

        Avoids a full :meth:`refresh_dedup_index` round-trip when only one
        item's metadata (e.g. ``collectionIds``) has changed.  Must be called
        after every :meth:`update_item` so subsequent ``get_existing_item``
        lookups on the same ``(folder, name)`` key return fresh data.
        """
        self._existing_entries.setdefault(folder, {})[name] = item

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
            timeout=_HTTP_TIMEOUT_S,
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
