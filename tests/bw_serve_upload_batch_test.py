"""Same-item uploads serialize; acknowledgements require post-sync byte checks."""

import asyncio
import io
import logging
from typing import cast

import httpx

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse
from kp2bw.exceptions import BitwardenClientError, BitwardenHttpError


class _UploadClient(BitwardenServeClient):
    def __init__(self, *, failure: str = "") -> None:
        self._base_url = "http://localhost"
        self._http_timeout = 1.0
        self.failure = failure
        self.active: set[str] = set()
        self.overlap = False
        self.synced = False
        self.files: dict[str, dict[str, bytes]] = {}
        self.uploads: list[tuple[str, str]] = []
        self.reads: list[tuple[str, str]] = []
        self.two_items_started = asyncio.Event()

    async def upload_attachment(
        self, client: httpx.AsyncClient, item_id: str, filename: str, data: bytes
    ) -> None:
        assert item_id not in self.active, "Concurrent mutations on the same item"
        self.active.add(item_id)
        assert len(self.active) <= 2, "Exceeded the configured global concurrency"
        if len(self.active) == 2:
            self.overlap = True
            self.two_items_started.set()
        try:
            # Both items must be able to start even with multiple A files queued
            # first. No timing-based assertion or reliance on network latency.
            await asyncio.wait_for(self.two_items_started.wait(), timeout=2)
            self.uploads.append((item_id, filename))
            if filename == "reject":
                raise BitwardenClientError("synthetic upload rejection")
            self.files.setdefault(item_id, {})[filename] = data
            await asyncio.sleep(0)
        finally:
            self.active.remove(item_id)

    def sync(self) -> None:
        assert not self.active, "Verification raced with an unfinished upload"
        if self.failure == "sync":
            raise BitwardenClientError("synthetic sync failure")
        self.synced = True
        if self.failure == "missing":
            self.files["a"].pop("two")
        elif self.failure == "corrupt":
            self.files["a"]["two"] = b"different remote bytes"

    def get_item(self, item_id: str) -> BwItemResponse:
        assert self.synced, "Verification must use post-sync metadata"
        if self.failure == "http-metadata" and item_id == "a":
            raise BitwardenHttpError(
                "Not found. synthetic-private-value", status_code=400
            )
        if self.failure == "metadata" and item_id == "a":
            raise BitwardenClientError("synthetic metadata failure")
        return cast(
            BwItemResponse,
            {
                "id": item_id,
                "attachments": [
                    {"id": name, "fileName": name} for name in self.files[item_id]
                ],
            },
        )

    def get_attachment(self, item_id: str, attachment_id: str) -> bytes:
        assert self.synced
        self.reads.append((item_id, attachment_id))
        if self.failure == "download" and attachment_id == "two":
            raise httpx.ReadError("synthetic download failure")
        return self.files[item_id][attachment_id]


async def _check_batch(failure: str = "") -> None:
    client = _UploadClient(failure=failure)
    # Repeated item IDs must share a lock even across separate input records.
    failed = await client.upload_attachments_parallel(
        [
            ("a", [("one", b"1"), ("two", b"2")]),
            ("a", [("three", b"3"), ("reject", b"4"), ("after-rejection", b"5")]),
            ("b", [("other", b"6")]),
            ("c", [("third", b"7")]),
        ],
        max_concurrency=2,
    )
    assert client.overlap, "Different items must retain parallelism"
    expected = {("a", "reject")}
    if failure in {"missing", "corrupt", "download"}:
        expected.add(("a", "two"))
    elif failure in {"sync", "metadata", "http-metadata"}:
        expected.update(
            ("a", name) for name in ("one", "two", "three", "after-rejection")
        )
        if failure == "sync":
            expected.add(("b", "other"))
            expected.add(("c", "third"))
    assert set(failed) == expected, (failure, failed)
    assert len(failed) == len(expected)
    if not failure:
        assert len(client.reads) == 6
    assert ("a", "after-rejection") in client.uploads, (
        "One failed file must not abort siblings"
    )


def _check_missing_item_recovery() -> None:
    for initial_status, message, recover in (
        (400, "Not found.", True),
        (404, "missing", True),
        (400, "Not found.", False),
        (400, "Vault is locked.", False),
        (403, "Permission denied", False),
    ):
        requests: list[tuple[str, str]] = []

        def respond(
            request: httpx.Request,
            requests: list[tuple[str, str]] = requests,
            recover: bool = recover,
            initial_status: int = initial_status,
            message: str = message,
        ) -> httpx.Response:
            requests.append((request.method, request.url.raw_path.decode()))
            if request.method == "POST":
                assert request.url.params["force"] == "true"
                return httpx.Response(200, json={"success": True, "data": {}})
            if len(requests) == 3 and recover:
                return httpx.Response(
                    200, json={"success": True, "data": {"id": "item"}}
                )
            return httpx.Response(
                initial_status, json={"success": False, "message": message}
            )

        client = object.__new__(BitwardenServeClient)
        with httpx.Client(
            transport=httpx.MockTransport(respond), base_url="http://bw.test"
        ) as http:
            client._http = http
            try:
                item = client.get_item("item")
            except BitwardenHttpError:
                assert not recover
            else:
                assert recover and item["id"] == "item"
        expected = [("GET", "/object/item/item")]
        if message == "Not found." or initial_status == 404:
            expected += [("POST", "/sync?force=true"), ("GET", "/object/item/item")]
        assert requests == expected


def main() -> None:
    _check_missing_item_recovery()
    for failure in ("", "missing", "corrupt", "download", "metadata", "sync"):
        asyncio.run(_check_batch(failure))
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    logger = logging.getLogger("kp2bw.bw_serve")
    logger.addHandler(handler)
    try:
        asyncio.run(_check_batch("http-metadata"))
    finally:
        logger.removeHandler(handler)
    assert "HTTP 400 (item not found)" in output.getvalue()
    assert "synthetic-private-value" not in output.getvalue()
    client = _UploadClient()
    assert asyncio.run(client.upload_attachments_parallel([])) == []
    try:
        asyncio.run(client.upload_attachments_parallel([], max_concurrency=0))
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid concurrency must fail instead of deadlocking")
    print("attachment batch serialization and verification tests passed")


if __name__ == "__main__":
    main()
