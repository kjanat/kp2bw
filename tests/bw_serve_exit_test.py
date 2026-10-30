"""A dead serve process aborts the batch; live disconnects still retry."""

import asyncio
import subprocess
import sys
from typing import cast
from unittest.mock import patch

import httpx

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemCreate
from kp2bw.exceptions import BitwardenServeExitedError


def _process() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _client(process: subprocess.Popen[bytes]) -> BitwardenServeClient:
    client = object.__new__(BitwardenServeClient)
    client._process = process
    client._bw_version = "2026.7.0"
    client._base_url = "http://serve.test"
    client._http_timeout = 1
    client._folders = {}
    return client


def assert_dead_process_aborts_batch() -> None:
    with _process() as process:
        client = _client(process)
        calls: list[str] = []
        failed: list[str] = []

        def crash(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            process.terminate()
            process.wait(timeout=5)
            raise httpx.RemoteProtocolError("sensitive raw crash output")

        with httpx.Client(
            transport=httpx.MockTransport(crash), base_url=client._base_url
        ) as client._http:
            item = cast(BwItemCreate, {"name": "fixture", "type": 1, "fields": []})
            try:
                client.create_items_batch(
                    {"one": (None, item), "two": (None, item)},
                    create_folders=False,
                    on_item_failed=lambda key, error: failed.append(key),
                )
            except BitwardenServeExitedError as exc:
                message = str(exc)
                assert "2026.7.0" in message and "#compatibility" in message
                assert "sensitive" not in message
            else:
                raise AssertionError("Dead serve must abort the batch")
            assert len(calls) == 1 and not failed, (
                "Dead serve was treated as per-item failure"
            )
            try:
                client.get_attachment("item", "file")
            except BitwardenServeExitedError:
                pass
            else:
                raise AssertionError(
                    "Downloads must also fail before contacting a dead serve"
                )
            assert len(calls) == 1


def assert_live_disconnect_retries() -> None:
    with _process() as process:
        try:
            client = _client(process)
            calls = 0

            def intermittent(request: httpx.Request) -> httpx.Response:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise httpx.RemoteProtocolError("temporary disconnect")
                return httpx.Response(
                    200, json={"success": True, "data": {"id": "item"}}
                )

            with httpx.Client(
                transport=httpx.MockTransport(intermittent), base_url=client._base_url
            ) as client._http:
                assert client.get_item("item")["id"] == "item"
                assert calls == 2 and process.poll() is None
        finally:
            process.terminate()
            process.wait(timeout=5)


def assert_async_death_propagates() -> None:
    with _process() as process:
        client = _client(process)

        async def crash() -> httpx.Response:
            process.terminate()
            process.wait(timeout=5)
            raise httpx.ConnectError("connection refused")

        async def run() -> None:
            try:
                await client._send_async_with_rate_limit_retry(
                    crash, method="POST", path="/attachment"
                )
            except BitwardenServeExitedError:
                pass
            else:
                raise AssertionError("Async upload transport must detect process death")

            async def upload(*args: object) -> None:
                client._check_serve_process()

            with patch.object(client, "upload_attachment", upload):
                try:
                    await client.upload_attachments_parallel([
                        ("item", [("file", b"test")])
                    ])
                except BitwardenServeExitedError:
                    pass
                else:
                    raise AssertionError(
                        "Async batch swallowed the fatal process error"
                    )

        asyncio.run(run())


def main() -> None:
    assert_dead_process_aborts_batch()
    assert_live_disconnect_retries()
    assert_async_death_propagates()
    print("serve process exit tests passed")


if __name__ == "__main__":
    main()
