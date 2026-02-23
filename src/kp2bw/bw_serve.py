"""Bitwarden CLI serve process lifecycle and HTTP transport."""

from __future__ import annotations

import atexit
import logging
import signal
import socket
import subprocess
import time
from collections.abc import Callable
from types import FrameType, TracebackType
from typing import Any, Self

import httpx

from .exceptions import BitwardenClientError

logger = logging.getLogger(__name__)

# How long to wait for `bw serve` to become responsive.
_SERVE_STARTUP_TIMEOUT_S: float = 30.0

# Polling interval when waiting for serve to start.
_SERVE_POLL_INTERVAL_S: float = 0.25

# Default HTTP timeout for individual requests.
_HTTP_TIMEOUT_S: float = 60.0


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

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __init__(
        self,
        password: str,
        *,
        org_id: str | None = None,
    ) -> None:
        self._port = _find_free_port()
        self._base_url = f"http://127.0.0.1:{self._port}"
        self._process = None
        self._http = httpx.Client(
            base_url=self._base_url,
            timeout=_HTTP_TIMEOUT_S,
        )
        self._org_id = org_id

        self._folders = {}

        self._start_serve()
        self._wait_for_ready()
        self._unlock(password)
        self._sync()

        # Populate folder cache from existing vault state.
        self._folders = self.list_folders()

        # Register cleanup handlers so the bw serve process is always
        # terminated — even on unhandled exceptions or signals.
        atexit.register(self.close)
        self._previous_sigterm = signal.getsignal(signal.SIGTERM)
        self._previous_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

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

    def _start_serve(self) -> None:
        """Spawn ``bw serve --port <port> --hostname localhost``."""
        cmd = ["bw", "serve", "--port", str(self._port), "--hostname", "localhost"]
        logger.debug(f"Starting bw serve on port {self._port}")
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _wait_for_ready(self) -> None:
        """Poll ``GET /status`` until the server is responsive."""
        deadline = time.monotonic() + _SERVE_STARTUP_TIMEOUT_S
        while time.monotonic() < deadline:
            # Check the process hasn't died.
            if self._process is not None and self._process.poll() is not None:
                raise BitwardenClientError(
                    f"bw serve exited unexpectedly with code {self._process.returncode}"
                )
            try:
                resp = self._http.get("/status")
                if resp.status_code == 200:
                    logger.debug("bw serve is ready")
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
        # Unregister atexit to avoid double-close.
        atexit.unregister(self.close)

        # Restore previous signal handlers.
        signal.signal(signal.SIGTERM, self._previous_sigterm)
        signal.signal(signal.SIGINT, self._previous_sigint)

        if self._process is not None and self._process.poll() is None:
            logger.debug("Terminating bw serve process")
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("bw serve did not exit on SIGTERM, sending SIGKILL")
                self._process.kill()
                self._process.wait(timeout=5)

        self._process = None
        self._http.close()

    def _signal_handler(self, signum: int, _frame: FrameType | None) -> None:
        """Handle SIGTERM/SIGINT by cleaning up, then re-raising."""
        self.close()
        # Re-raise so the caller sees the expected signal behaviour.
        previous = (
            self._previous_sigterm
            if signum == signal.SIGTERM
            else self._previous_sigint
        )
        if isinstance(previous, int) or previous is None:
            # SIG_DFL / SIG_IGN / None — just exit.
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
        json_body: dict[str, Any] | None = None,
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

        body: dict[str, Any] = resp.json()
        if not body.get("success", False):
            msg = body.get("message", "unknown error")
            raise BitwardenClientError(f"bw serve error on {method} {path}: {msg}")

        return body.get("data", {})

    # ------------------------------------------------------------------
    # Vault operations (lifecycle)
    # ------------------------------------------------------------------

    def _unlock(self, password: str) -> None:
        """Unlock the vault via ``POST /unlock``."""
        logger.debug("Unlocking vault via bw serve")
        self._request("POST", "/unlock", json_body={"password": password})

    def _sync(self) -> None:
        """Synchronise vault state via ``POST /sync``."""
        logger.debug("Syncing vault via bw serve")
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
        folders: list[dict[str, Any]] = data.get("data", [])
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
        logger.debug(f"Created folder {name!r} → {folder_id}")
        return folder_id

    def has_folder(self, name: str) -> bool:
        """Check whether a folder with the given name exists."""
        return name in self._folders

    # ------------------------------------------------------------------
    # CRUD — items
    # ------------------------------------------------------------------

    def list_items(self, *, folder_id: str | None = None) -> list[dict[str, Any]]:
        """Return all vault items, optionally filtered by folder ID."""
        params: dict[str, str] | None = None
        if folder_id is not None:
            params = {"folderid": folder_id}
        data = self._request("GET", "/list/object/items", params=params)
        items: list[dict[str, Any]] = data.get("data", [])
        return items

    def create_item(self, item: dict[str, Any]) -> str:
        """Create a single vault item via HTTP and return its ID."""
        data = self._request("POST", "/object/item", json_body=item)
        item_id: str = data["id"]
        logger.debug(f"Created item {item.get('name', '?')!r} → {item_id}")
        return item_id

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
