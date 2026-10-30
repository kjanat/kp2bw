"""Bitwarden rate-limit rejections are waited out and retried (issue #65).

Bitwarden Cloud answers a burst of writes with HTTP 429 "Slow down! Too many
requests. Try again in 1s." (or ``1m`` once the per-minute quota is spent).
``bw serve`` forwards that as HTTP 400 with the 429 only in the message text,
so each create used to be skipped and a large import needed many re-runs.
These checks drive the real request paths over ``httpx.MockTransport``.
"""

import asyncio
import json
import logging
import math
import time
from collections.abc import Callable
from typing import Any

import httpx

from kp2bw.bw_serve import (
    BitwardenServeClient,
    rate_limit_wait_s,
    send_with_rate_limit_retry,
)
from kp2bw.bw_types import BwItemCreate, BwItemLogin
from kp2bw.exceptions import BitwardenClientError, BitwardenHttpError

_SERVER_BODY = (
    '{{"message":"Slow down! Too many requests. Try again in {period}.",'
    '"validationErrors":null,"exceptionMessage":null,"exceptionStackTrace":null,'
    '"innerExceptionMessage":null,"object":"error"}}'
)


def _sdk_message(period: str) -> str:
    """The message ``bw serve`` returns for an SDK create rejected with 429."""
    return (
        "CreateCipherError: error in response: status code 429 Too Many Requests: "
        + _SERVER_BODY.format(period=period)
    )


_LEGACY_MESSAGE = "Rate limit exceeded. Try again later."


def _item(name: str) -> BwItemCreate:
    return BwItemCreate(
        organizationId=None,
        collectionIds=None,
        folderId=None,
        type=1,
        name=name,
        notes=None,
        favorite=False,
        fields=[],
        secureNote=None,
        card=None,
        identity=None,
        login=BwItemLogin(
            uris=[], username="", password="", totp=None, passwordRevisionDate=None
        ),
    )


def _serve_error(message: str) -> httpx.Response:
    return httpx.Response(400, json={"success": False, "message": message})


def _serve_ok(data: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": data})


class _Script:
    """Hands out queued responses in order and records each request."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = list(responses)
        self.requests: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        if not self._responses:
            raise AssertionError(f"unexpected request {request.method} {request.url}")
        return self._responses.pop(0)


def _client(script: _Script) -> tuple[BitwardenServeClient, list[float]]:
    """A client bound to *script* whose sleeps are recorded, not slept."""
    inst = object.__new__(BitwardenServeClient)
    inst._http = httpx.Client(
        transport=httpx.MockTransport(script), base_url="http://bw.test"
    )
    inst._folders = {}
    sleeps: list[float] = []
    inst._sleep = sleeps.append
    return inst, sleeps


class _Warnings(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _capture_warnings(run: Callable[[], object]) -> list[str]:
    handler = _Warnings()
    log = logging.getLogger("kp2bw.bw_serve")
    log.addHandler(handler)
    try:
        run()
    finally:
        log.removeHandler(handler)
    return handler.messages


def _body(message: str) -> str:
    return json.dumps({"success": False, "message": message})


def assert_wait_honours_named_period() -> None:
    cases = {"1s": 1.0, "1m": 60.0, "0.5s": 0.5, "2S": 2.0}
    for period, expected in cases.items():
        got = rate_limit_wait_s(400, _body(_sdk_message(period)), attempt=1)
        if got != expected:
            raise AssertionError(
                f"'Try again in {period}' must wait {expected}s, got {got}"
            )


def assert_wait_backs_off_without_named_period() -> None:
    got = [
        rate_limit_wait_s(400, _body(_LEGACY_MESSAGE), attempt=n) for n in range(1, 9)
    ]
    if got != [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0]:
        raise AssertionError(f"legacy rate limit must back off to the cap, got {got}")
    raw = rate_limit_wait_s(429, "", attempt=2)
    if raw is None or not math.isclose(raw, 2.0):
        raise AssertionError(f"a bare HTTP 429 must back off too, got {raw}")


def assert_wait_declines_non_rate_limits() -> None:
    cases: list[tuple[int, str]] = [
        (400, _body("Premium status is required to use this feature.")),
        (400, _body("Not found.")),
        (200, json.dumps({"success": True, "data": {"name": "Too many requests"}})),
    ]
    for status, body in cases:
        got = rate_limit_wait_s(status, body, attempt=1)
        if got is not None:
            raise AssertionError(
                f"HTTP {status} {body!r} is not a rate limit, got {got}"
            )


def assert_wait_declines_past_budget_or_cap() -> None:
    spent = rate_limit_wait_s(400, _body(_sdk_message("1s")), attempt=9)
    if spent is not None:
        raise AssertionError(f"retry 9 exceeds the budget of 8, got {spent}")
    hour = rate_limit_wait_s(400, _body(_sdk_message("60m")), attempt=1)
    if hour is not None:
        raise AssertionError(f"an hour-long window must not be waited out, got {hour}")


def assert_send_returns_first_non_rate_limited_response() -> None:
    responses = [
        _serve_error(_sdk_message("1s")),
        _serve_error(_sdk_message("1m")),
        _serve_ok({"id": "x"}),
    ]
    sleeps: list[float] = []
    got = send_with_rate_limit_retry(
        lambda: responses.pop(0),
        method="POST",
        path="/object/item",
        sleep=sleeps.append,
    )
    if got.status_code != 200 or sleeps != [1.0, 60.0]:
        raise AssertionError(
            f"expected 200 after waits [1, 60], got {got.status_code} {sleeps}"
        )


def assert_create_item_retries_rate_limited_post() -> None:
    script = _Script([
        _serve_error(_sdk_message("1s")),
        _serve_error(_sdk_message("1m")),
        _serve_ok({"id": "item-1"}),
    ])
    bw, sleeps = _client(script)
    created: list[str] = []
    warnings = _capture_warnings(
        lambda: created.append(bw.create_item(_item("Working Spirit")))
    )
    if created != ["item-1"]:
        raise AssertionError(f"the retried create must return its id, got {created}")
    if script.requests != [("POST", "/object/item")] * 3:
        raise AssertionError(f"expected three POSTs, got {script.requests}")
    if sleeps != [1.0, 60.0]:
        raise AssertionError(f"expected waits [1, 60], got {sleeps}")
    expected = [
        "Bitwarden rate limit on POST /object/item; waiting 1s (retry 1/8)",
        "Bitwarden rate limit on POST /object/item; waiting 60s (retry 2/8)",
    ]
    if warnings != expected:
        raise AssertionError(f"each wait must be logged, got {warnings}")


def assert_exhausted_budget_raises_the_rate_limit_error() -> None:
    script = _Script([_serve_error(_LEGACY_MESSAGE) for _ in range(9)])
    bw, sleeps = _client(script)
    try:
        bw.create_folder("Work")
    except BitwardenHttpError as exc:
        if "Rate limit exceeded" not in str(exc) or exc.status_code != 400:
            raise AssertionError(
                f"the final rejection must be reported, got {exc}"
            ) from None
    else:
        raise AssertionError("a request rate-limited past the budget must raise")
    if len(script.requests) != 9 or len(sleeps) != 8:
        raise AssertionError(
            f"expected 9 attempts and 8 waits, got {len(script.requests)} / {len(sleeps)}"
        )


def assert_other_errors_are_not_retried() -> None:
    script = _Script([_serve_error("Premium status is required to use this feature.")])
    bw, sleeps = _client(script)
    try:
        bw.create_folder("Work")
    except BitwardenHttpError:
        pass
    else:
        raise AssertionError("a non-rate-limit 400 must raise")
    if len(script.requests) != 1 or sleeps:
        raise AssertionError(
            f"a non-rate-limit 400 must not retry: {script.requests} {sleeps}"
        )


def assert_batch_import_survives_rate_limits() -> None:
    """The #65 scenario: no item is skipped when Bitwarden throttles mid-batch."""
    script = _Script([
        _serve_ok({"id": "folder-1"}),
        _serve_ok({"id": "item-a"}),
        _serve_error(_sdk_message("1s")),
        _serve_ok({"id": "item-b"}),
        _serve_error(_sdk_message("1m")),
        _serve_ok({"id": "item-c"}),
    ])
    bw, sleeps = _client(script)
    failed: list[str] = []
    entries: dict[str, tuple[str | None, BwItemCreate]] = {
        "a": ("Work", _item("a")),
        "b": ("Work", _item("b")),
        "c": (None, _item("c")),
    }
    key_to_id = bw.create_items_batch(
        entries, on_item_failed=lambda key, _: failed.append(key)
    )
    if key_to_id != {"a": "item-a", "b": "item-b", "c": "item-c"} or failed:
        raise AssertionError(
            f"every item must be created, got {key_to_id} failed={failed}"
        )
    if sleeps != [1.0, 60.0]:
        raise AssertionError(f"expected waits [1, 60], got {sleeps}")


def assert_get_attachment_retries_rate_limit() -> None:
    script = _Script([
        _serve_error(_LEGACY_MESSAGE),
        httpx.Response(200, content=b"file bytes"),
    ])
    bw, sleeps = _client(script)
    got = bw.get_attachment("item-1", "att-1")
    if got != b"file bytes" or sleeps != [1.0]:
        raise AssertionError(f"expected bytes after one wait, got {got!r} {sleeps}")
    if script.requests != [("GET", "/object/attachment/att-1")] * 2:
        raise AssertionError(f"expected two GETs, got {script.requests}")


def _upload(script: _Script) -> list[float]:
    inst, sleeps = _client(script)

    async def record(seconds: float) -> None:
        sleeps.append(seconds)

    inst._async_sleep = record

    async def run() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(script), base_url="http://bw.test"
        ) as client:
            await inst.upload_attachment(client, "item-1", "notes.txt", b"hello")

    try:
        asyncio.run(run())
    finally:
        inst._http.close()
    return sleeps


def assert_upload_attachment_retries_rate_limit() -> None:
    script = _Script([_serve_error(_LEGACY_MESSAGE), _serve_ok({"id": "item-1"})])
    sleeps = _upload(script)
    if script.requests != [("POST", "/attachment")] * 2 or sleeps != [1.0]:
        raise AssertionError(
            f"expected one wait then a retry, got {script.requests} {sleeps}"
        )


def assert_upload_sync_retries_rate_limit() -> None:
    script = _Script([
        _serve_error("Not found."),
        _serve_error("Not found."),
        _serve_error(_LEGACY_MESSAGE),
        _serve_ok({}),
        _serve_ok({"id": "item-1"}),
        _serve_ok({"id": "attachment-1"}),
    ])
    sleeps = _upload(script)
    paths = [path for _, path in script.requests]
    if paths != [
        "/attachment",
        "/object/item/item-1",
        "/sync",
        "/sync",
        "/object/item/item-1",
        "/attachment",
    ] or sleeps != [1.0]:
        raise AssertionError(
            f"the self-heal sync must be retried, got {paths} {sleeps}"
        )


def assert_upload_exhausted_budget_raises() -> None:
    script = _Script([_serve_error(_sdk_message("1s")) for _ in range(9)])
    try:
        _upload(script)
    except BitwardenClientError as exc:
        if "429" not in str(exc):
            raise AssertionError(
                f"the final rejection must be reported, got {exc}"
            ) from None
        return
    raise AssertionError("an upload rate-limited past the budget must raise")


def assert_default_sleepers_wait_for_real() -> None:
    script = _Script([
        _serve_error(_sdk_message("0.01s")),
        _serve_ok({"id": "folder-1"}),
        _serve_error(_sdk_message("0.01s")),
        _serve_ok({"id": "item-1"}),
    ])
    inst = object.__new__(BitwardenServeClient)
    inst._folders = {}

    async def upload() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(script), base_url="http://bw.test"
        ) as client:
            await inst.upload_attachment(client, "item-1", "notes.txt", b"hello")

    with httpx.Client(
        transport=httpx.MockTransport(script), base_url="http://bw.test"
    ) as http:
        inst._http = http
        started = time.monotonic()
        folder_id = inst.create_folder("Work")
        asyncio.run(upload())
        elapsed = time.monotonic() - started
    if folder_id != "folder-1" or elapsed < 0.02:
        raise AssertionError(
            f"both default sleepers must wait, got {folder_id} {elapsed}"
        )


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_wait_honours_named_period()
    assert_wait_backs_off_without_named_period()
    assert_wait_declines_non_rate_limits()
    assert_wait_declines_past_budget_or_cap()
    assert_send_returns_first_non_rate_limited_response()
    assert_create_item_retries_rate_limited_post()
    assert_exhausted_budget_raises_the_rate_limit_error()
    assert_other_errors_are_not_retried()
    assert_batch_import_survives_rate_limits()
    assert_get_attachment_retries_rate_limit()
    assert_upload_attachment_retries_rate_limit()
    assert_upload_sync_retries_rate_limit()
    assert_upload_exhausted_budget_raises()
    assert_default_sleepers_wait_for_real()
    print("bw serve rate limit test passed")


if __name__ == "__main__":
    main()
