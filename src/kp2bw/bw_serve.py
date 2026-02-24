"""Bitwarden CLI serve process lifecycle and HTTP transport."""

import asyncio
import atexit
import logging
import os
import signal
import socket
import subprocess
import time
from collections.abc import Callable
from types import FrameType, TracebackType
from typing import Any, Self

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
    _closed: bool

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
        self._closed = False
        self._http = httpx.Client(
            base_url=self._base_url,
            timeout=_HTTP_TIMEOUT_S,
        )
        self._org_id = org_id

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
                ["bw", "unlock", "--raw", "--passwordenv", "_KP2BW_BW_PW"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                stdin=subprocess.DEVNULL,
                env={**os.environ, "_KP2BW_BW_PW": password},
            )
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
        cmd = ["bw", "serve", "--port", str(self._port), "--hostname", "127.0.0.1"]
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
        self._process = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
        )

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
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("bw serve did not exit on SIGTERM, sending SIGKILL")
                self._process.kill()
                self._process.wait(timeout=5)

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
    ) -> list[BwItemResponse]:
        """Return vault items, optionally filtered by folder or organization ID."""
        params: dict[str, str] = {}
        if folder_id is not None:
            params["folderid"] = folder_id
        if organization_id is not None:
            params["organizationId"] = organization_id
        data = self._request("GET", "/list/object/items", params=params or None)
        items: list[BwItemResponse] = data.get("data", [])
        return items

    def create_item(self, item: BwItemCreate) -> str:
        """Create a single vault item via HTTP and return its ID."""
        data = self._request("POST", "/object/item", json_body=item)  # type: ignore[arg-type]
        item_id: str = data["id"]
        logger.log(VERBOSE, f"Created item {item.get('name', '?')!r} → {item_id}")
        return item_id

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        """Replace an existing vault item via ``PUT /object/item/{id}``.

        The API requires the full object in the request body — partial updates
        are not supported.
        """
        self._request("PUT", f"/object/item/{item_id}", json_body=item)  # type: ignore[arg-type]
        logger.log(VERBOSE, f"Updated item {item.get('name', '?')!r} ({item_id})")

    def create_items_batch(
        self,
        entries: dict[str, tuple[str | None, BwItemCreate]],
    ) -> dict[str, str]:
        """Create folders and items via HTTP, returning ``{key: item_id}``.

        *entries* maps arbitrary keys to ``(folder_name, bw_item_dict)`` tuples.
        Folders are created/resolved first, then items are created sequentially
        with the correct ``folderId`` bound.
        """
        # Ensure all required folders exist.
        folder_names = {fname for fname, _ in entries.values() if fname}
        for fname in sorted(folder_names):
            self.create_folder(fname)

        key_to_id: dict[str, str] = {}
        total = len(entries)
        for idx, (key, (folder_name, bw_item)) in enumerate(entries.items(), 1):
            # Bind folder ID — create a new typed dict rather than mutating.
            item: BwItemCreate = {
                **bw_item,
                "folderId": self._folders.get(folder_name) if folder_name else None,
            }
            item_id = self.create_item(item)
            key_to_id[key] = item_id

            if idx % 25 == 0 or idx == total:
                logger.info(f"  Created {idx}/{total} items")

        return key_to_id

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _build_dedup_index(self) -> dict[str | None, dict[str, BwItemResponse]]:
        """Build a ``{folder_name: {item_name: item}}`` index for O(1) dedup.

        Stores the full item response so callers can inspect ``collectionIds``
        and call :meth:`update_item` without an extra GET.

        When an organization ID is configured, only items belonging to that
        organization are indexed so personal-vault entries don't shadow the
        (empty) org vault during import.
        """
        id_to_name: dict[str, str] = {
            fid: fname for fname, fid in self._folders.items()
        }
        index: dict[str | None, dict[str, BwItemResponse]] = {}
        for item in self.list_items(organization_id=self._org_id):
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
    # Async attachment uploads
    # ------------------------------------------------------------------

    async def upload_attachment(
        self,
        client: httpx.AsyncClient,
        item_id: str,
        filename: str,
        data: bytes,
    ) -> None:
        """Upload one attachment via multipart ``POST /attachment``."""
        resp = await client.post(
            "/attachment",
            params={"itemid": item_id},
            files={"file": (filename, data)},
        )
        if resp.status_code >= 400:
            raise BitwardenClientError(
                f"Attachment upload failed for {filename!r} on item {item_id}: "
                f"HTTP {resp.status_code}"
            )

        try:
            body: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise BitwardenClientError(
                f"Attachment upload returned non-JSON response "
                f"(HTTP {resp.status_code}) for {filename!r} on item {item_id}"
            ) from exc

        if not body.get("success", False):
            msg = body.get("message", "unknown error")
            raise BitwardenClientError(
                f"Attachment upload error for {filename!r}: {msg}"
            )
        logger.log(VERBOSE, f"Uploaded attachment {filename!r} to item {item_id}")

    async def upload_attachments_parallel(
        self,
        items: list[tuple[str, list[tuple[str, bytes]]]],
        *,
        max_concurrency: int = 4,
    ) -> None:
        """Upload all attachments with bounded parallelism.

        *items* is a list of ``(item_id, [(filename, data), ...])`` tuples.
        """
        total = sum(len(atts) for _, atts in items)
        if total == 0:
            return

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
            labels: list[str] = []
            for item_id, attachments in items:
                for filename, data in attachments:
                    tasks.append(
                        asyncio.create_task(
                            _upload_one(client, item_id, filename, data)
                        )
                    )
                    labels.append(f"{filename} (item {item_id})")
            results = await asyncio.gather(*tasks, return_exceptions=True)

        failed_labels: list[str] = []
        for label, result in zip(labels, results, strict=True):
            if isinstance(result, BaseException):
                logger.error(f"Attachment upload failed for {label}: {result}")
                failed_labels.append(label)
        if failed_labels:
            summary = ", ".join(failed_labels[:5])
            if len(failed_labels) > 5:
                summary += f", ... (+{len(failed_labels) - 5} more)"
            raise BitwardenClientError(
                f"{len(failed_labels)}/{total} attachment uploads failed: {summary}"
            )

        logger.info(f"Uploaded {total} attachments")

    def upload_attachments(
        self,
        items: list[tuple[str, list[tuple[str, bytes]]]],
        *,
        max_concurrency: int = 4,
    ) -> None:
        """Synchronous wrapper for :meth:`upload_attachments_parallel`."""
        asyncio.run(
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
