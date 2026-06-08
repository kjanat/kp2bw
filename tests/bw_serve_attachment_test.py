"""Checks that attachment-upload errors surface the server's real reason (#11).

``bw serve`` reports command-level failures (e.g. "Premium status is required",
storage-quota or size limits) as HTTP 400 with the reason in the JSON body's
``message`` field.  kp2bw used to discard the body and raise an opaque
``HTTP 400``; these checks lock in that the real message is now reported.
"""

import asyncio
from typing import Any, cast

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.exceptions import BitwardenClientError

_NO_JSON = object()


class _FakeResponse:
    """Minimal httpx.Response stand-in for the attachment endpoint."""

    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

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


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_server_message_is_surfaced()
    assert_opaque_status_when_no_message()
    assert_success_does_not_raise()
    assert_command_error_on_2xx_is_surfaced()
    print("bw serve attachment test passed")


if __name__ == "__main__":
    main()
