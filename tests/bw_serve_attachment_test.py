"""Checks that attachment-upload errors surface the server's real reason (#11).

``bw serve`` reports command-level failures (e.g. "Premium status is required",
storage-quota or size limits) as HTTP 400 with the reason in the JSON body's
``message`` field.  kp2bw used to discard the body and raise an opaque
``HTTP 400``; these checks lock in that the real message is now reported.
"""

import asyncio
import json
from typing import Any, cast
from unittest.mock import patch

import httpx

from kp2bw.bw_serve import BitwardenServeClient, _UploadCacheGate
from kp2bw.exceptions import BitwardenClientError

_NO_JSON = object()


class _FakeResponse:
    """Minimal httpx.Response stand-in for the attachment endpoint."""

    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    @property
    def text(self) -> str:
        return "" if self._payload is _NO_JSON else json.dumps(self._payload)

    def json(self) -> Any:
        if self._payload is _NO_JSON:
            raise ValueError("response body is not JSON")
        return self._payload


class _FakeAsyncClient:
    """Records the POST and returns a canned response."""

    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.posted: list[tuple[str, Any, Any]] = []

    async def post(
        self, path: str, *, params: Any = None, files: Any = None
    ) -> _FakeResponse:
        self.posted.append((path, params, files))
        return self._response


class _ScriptedAsyncClient:
    """Returns queued responses in call order; records every POST path.

    Lets a test drive a rejected upload followed by one retry after recovery.
    """

    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = list(responses)
        self.posted: list[tuple[str, Any, Any]] = []

    async def post(
        self, path: str, *, params: Any = None, files: Any = None
    ) -> _FakeResponse:
        self.posted.append((path, params, files))
        if not self._responses:
            raise AssertionError(f"unexpected extra POST to {path!r}")
        return self._responses.pop(0)


def _run_upload(response: _FakeResponse) -> _FakeAsyncClient:
    """Invoke the (self-free) upload_attachment coroutine against a fake client."""
    inst = object.__new__(BitwardenServeClient)  # no bw serve process spawned
    client = _FakeAsyncClient(response)
    asyncio.run(
        inst.upload_attachment(
            cast(Any, client), "item-1", "photo.jpg", b"\xff\xd8\xff"
        )
    )
    return client


def _run_upload_scripted(responses: list[_FakeResponse]) -> _ScriptedAsyncClient:
    """Invoke upload_attachment against a client with sequenced responses."""
    inst = object.__new__(BitwardenServeClient)
    client = _ScriptedAsyncClient(responses)
    with patch.object(inst, "get_item", return_value={"id": "item-1"}) as read:
        try:
            asyncio.run(
                inst.upload_attachment(
                    cast(Any, client), "item-1", "notes.txt", b"hello"
                )
            )
        finally:
            read.assert_called_once_with("item-1")
    return client


def assert_server_message_is_surfaced() -> None:
    resp = _FakeResponse(
        400,
        {
            "success": False,
            "message": "Premium status is required to use this feature.",
        },
    )
    try:
        _run_upload(resp)
    except BitwardenClientError as exc:
        text = str(exc)
        if "Premium status is required" not in text:
            raise AssertionError(f"server message not surfaced: {text!r}") from None
        if "photo.jpg" not in text:
            raise AssertionError(f"filename missing from error: {text!r}") from None
        return
    raise AssertionError("an HTTP 400 response must raise BitwardenClientError")


def assert_opaque_status_when_no_message() -> None:
    try:
        _run_upload(_FakeResponse(400, _NO_JSON))
    except BitwardenClientError as exc:
        if "HTTP 400" not in str(exc):
            raise AssertionError(f"expected HTTP 400 fallback, got: {exc}") from None
        return
    raise AssertionError("a non-JSON 400 must still raise")


def assert_success_does_not_raise() -> None:
    client = _run_upload(_FakeResponse(200, {"success": True, "data": {"id": "x"}}))
    if not client.posted:
        raise AssertionError("upload should POST to the attachment endpoint")
    path, params, _files = client.posted[0]
    if path != "/attachment" or params != {"itemid": "item-1"}:
        raise AssertionError(f"unexpected attachment request: {path} {params}")


def assert_command_error_on_2xx_is_surfaced() -> None:
    # bw serve can report a command-level failure as HTTP 200 with
    # success:false; the message must still be surfaced.
    resp = _FakeResponse(200, {"success": False, "message": "attachment rejected"})
    try:
        _run_upload(resp)
    except BitwardenClientError as exc:
        if "attachment rejected" not in str(exc):
            raise AssertionError(f"server message not surfaced: {exc}") from None
        return
    raise AssertionError("a success:false response must raise even on HTTP 200")


def assert_not_found_syncs_and_retries() -> None:
    # A just-created item is momentarily unresolvable by bw serve's attachment
    # endpoint (it resolves `itemid` from local cache). The first upload fails
    # with "Not found"; kp2bw must sync and retry, and the retry succeeds.
    not_found = _FakeResponse(200, {"success": False, "message": "Not found."})
    success = _FakeResponse(200, {"success": True, "data": {"id": "x"}})
    client = _run_upload_scripted([not_found, success])
    paths = [path for path, _params, _files in client.posted]
    if paths != ["/attachment", "/attachment"]:
        raise AssertionError(f"expected sync-and-retry, got POST sequence: {paths}")


def assert_persistent_not_found_raises_after_one_retry() -> None:
    # A not-found that survives the sync must raise (no infinite retry loop),
    # and only one sync is attempted.
    responses = [
        _FakeResponse(404, _NO_JSON),
        _FakeResponse(404, _NO_JSON),
    ]
    try:
        client = _run_upload_scripted(responses)
    except BitwardenClientError:
        return
    paths = [path for path, _params, _files in client.posted]
    raise AssertionError(
        f"a persistent not-found must raise after one retry; posts: {paths}"
    )


async def _check_concurrent_recovery() -> None:
    inst = object.__new__(BitwardenServeClient)
    active: set[str] = set()
    both_started = asyncio.Event()
    calls: dict[str, int] = {}
    reads: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/attachment"
        item_id = request.url.params["itemid"]
        calls[item_id] = calls.get(item_id, 0) + 1
        active.add(item_id)
        try:
            if calls[item_id] == 1:
                if len(active) == 2:
                    both_started.set()
                await asyncio.wait_for(both_started.wait(), timeout=2)
                return httpx.Response(
                    400, json={"success": False, "message": "Not found."}
                )
            assert item_id in reads, "Upload retried before item became readable"
            return httpx.Response(200, json={"success": True})
        finally:
            active.remove(item_id)

    def recover(item_id: str) -> dict[str, str]:
        assert not active, "Cache refresh overlaps an upload"
        reads.append(item_id)
        return {"id": item_id}

    with patch.object(inst, "get_item", side_effect=recover):
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(respond), base_url="http://bw.test"
        ) as client:
            await asyncio.wait_for(
                asyncio.gather(
                    inst.upload_attachment(client, "a", "one", b"one"),
                    inst.upload_attachment(client, "b", "two", b"two"),
                ),
                timeout=5,
            )
    assert both_started.is_set(), "Different items must retain parallelism"
    assert calls == {"a": 2, "b": 2}
    assert sorted(reads) == ["a", "b"]


async def _check_cancelled_refresh_releases_waiters() -> None:
    gate = _UploadCacheGate()
    waiting = asyncio.Event()

    async def refresh() -> None:
        waiting.set()
        async with gate.refreshing():
            raise AssertionError("Refresh entered while an upload was active")

    async with gate.uploading():
        task = asyncio.create_task(refresh())
        await waiting.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # A cancelled refresh must not leave later parallel uploads blocked.
        async with asyncio.timeout(2), gate.uploading():
            pass
    async with asyncio.timeout(2), gate.refreshing():
        pass


def assert_failed_recovery_does_not_repeat_upload() -> None:
    inst = object.__new__(BitwardenServeClient)
    client = _ScriptedAsyncClient([
        _FakeResponse(404, _NO_JSON),
    ])
    with patch.object(inst, "get_item", side_effect=BitwardenClientError("missing")):
        try:
            asyncio.run(inst.upload_attachment(cast(Any, client), "a", "one", b"one"))
        except BitwardenClientError:
            pass
        else:
            raise AssertionError("Failed recovery must abort the upload")
    assert len(client.posted) == 1


def main() -> None:
    """Run the script-style assertions and report success."""
    asyncio.run(_check_concurrent_recovery())
    asyncio.run(_check_cancelled_refresh_releases_waiters())
    assert_failed_recovery_does_not_repeat_upload()
    assert_server_message_is_surfaced()
    assert_opaque_status_when_no_message()
    assert_success_does_not_raise()
    assert_command_error_on_2xx_is_surfaced()
    assert_not_found_syncs_and_retries()
    assert_persistent_not_found_raises_after_one_retry()
    print("bw serve attachment test passed")


if __name__ == "__main__":
    main()
