"""Incomplete post-sync lists must not authorize duplicate imports."""

import json
import subprocess
from typing import Any
from unittest.mock import patch

import httpx

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.exceptions import BitwardenClientError
from kp2bw.inventory import inventory_signature


def main() -> None:
    collection = {
        "id": "collection",
        "organizationId": "org",
        "name": "Shared",
        "externalId": None,
    }
    cli_collection = {**collection, "object": "collection"}
    http_collection: dict[str, Any] = {
        **collection,
        "object": "org-collection",
        "users": [],
        "groups": [],
    }
    assert inventory_signature(
        [cli_collection], kind="org-collections"
    ) == inventory_signature([http_collection], kind="org-collections")
    for field in ("id", "organizationId", "name", "externalId"):
        assert inventory_signature(
            [cli_collection], kind="org-collections"
        ) != inventory_signature(
            [{**http_collection, field: "changed"}], kind="org-collections"
        )
    items: list[dict[str, Any]] = [
        {
            "id": "one",
            "name": "Café ☕ 日本語",
            "type": 1,
            "revisionDate": "new",
            "fields": [{"name": "KP2BW_ID", "value": "source", "type": 0}],
        },
        {"id": "two", "name": "Other", "type": 1, "revisionDate": "new", "fields": []},
    ]
    assert inventory_signature(items) == inventory_signature(list(reversed(items)))
    invalid_cases: list[object] = [{}, [{}], [items[0], items[0]]]
    for invalid in invalid_cases:
        try:
            inventory_signature(invalid)
        except BitwardenClientError:
            pass
        else:
            raise AssertionError(
                "Malformed inventory must not look like an empty vault"
            )
    stale_cases: list[list[dict[str, Any]]] = [
        [],
        items[:1],
        [{**items[0], "revisionDate": "old"}, items[1]],
    ]
    for stale in stale_cases:
        for recovers in (True, False):
            client = object.__new__(BitwardenServeClient)
            client.organization_id = None
            client.collection_id = None
            client.folder_cache = {}
            client.cli_command = ["synthetic-bw"]
            client.cli_cwd = None
            client.http_timeout = 30
            client.inventory_session = "synthetic-session"
            client.inventory_needs_check = True
            client.sleep = lambda _: None
            reads = 0
            commands = 0

            def respond(
                request: httpx.Request,
                recovers: bool = recovers,
                stale: list[dict[str, Any]] = stale,
            ) -> httpx.Response:
                nonlocal reads
                if request.method == "POST" and request.url.path == "/sync":
                    return httpx.Response(200, json={"success": True, "data": {}})
                assert request.method == "GET", (
                    "Inventory verification must never write"
                )
                rows = []
                if request.url.path.endswith("/items"):
                    reads += 1
                    rows = items if recovers and reads > 1 else stale
                return httpx.Response(
                    200, json={"success": True, "data": {"data": rows}}
                )

            def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
                nonlocal commands
                commands += 1
                assert args[:2] == ["synthetic-bw", "list"]
                assert kwargs["env"]["BW_SESSION"] == "synthetic-session"
                assert kwargs["env"]["VW_SESSION"] == "synthetic-session"
                assert kwargs["env"]["BW_NOINTERACTION"] == "true"
                assert kwargs["stdin"] == subprocess.DEVNULL
                assert kwargs["encoding"] == "utf-8"
                return subprocess.CompletedProcess(
                    args,
                    0,
                    json.dumps(items if args[2] == "items" else [], ensure_ascii=False),
                    "",
                )

            client.http = httpx.Client(
                base_url="http://localhost", transport=httpx.MockTransport(respond)
            )
            try:
                with patch("kp2bw.bw_serve.subprocess.run", side_effect=run):
                    if recovers:
                        client.build_dedup_index()
                        assert client.get_item_by_uuid("source") is not None
                        client.list_items()
                        assert commands == 2, (
                            "Repeated inventory reads must reuse verification until sync"
                        )
                        client.sync()
                        client.list_items()
                        assert commands == 4, (
                            "A new sync must invalidate inventory verification"
                        )
                    else:
                        try:
                            client.build_dedup_index()
                        except BitwardenClientError as exc:
                            assert "incomplete inventory" in str(exc)
                        else:
                            raise AssertionError(
                                "Stale inventory must not become a dedup index"
                            )
            finally:
                client.http.close()
    print("post-sync inventory verification tests passed")


if __name__ == "__main__":
    main()
