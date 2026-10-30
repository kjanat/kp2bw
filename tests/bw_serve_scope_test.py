"""Exercise scope consumers against an overbroad official-CLI-style list."""

import copy
from types import TracebackType
from typing import Self, cast
from unittest.mock import patch

import httpx

from kp2bw import cli
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse
from kp2bw.item_sync import stamp_content


def unused_item(
    item_id: str, org: str | None, collections: list[str]
) -> BwItemResponse:
    item = cast(
        BwItemResponse,
        {
            "id": item_id,
            "name": item_id,
            "type": 1,
            "organizationId": org,
            "collectionIds": collections,
            "folderId": "folder",
            "revisionDate": "2026-10-29T00:00:00Z",
            "fields": [
                {"name": "KP2BW_ID", "value": "shared-source-uuid", "type": 0},
                {
                    "name": "KP2A_URL",
                    "value": f"https://{item_id}.example.test",
                    "type": 0,
                },
            ],
            "login": {"uris": [{"uri": f"https://{item_id}.example.test", "match": 0}]},
        },
    )
    stamp_content(item)
    return item


class ScopeClient(BitwardenServeClient):
    def __init__(self, *, reverse: bool = False) -> None:
        self.organization_id = "org"
        self.collection_id = "inside"
        self.folder_cache = {}
        items = [
            unused_item("inside", "org", ["inside"]),
            unused_item("outside", "org", ["outside"]),
            unused_item("other-org", "other", ["inside"]),
            unused_item("personal", None, []),
            unused_item("missing", None, []),
        ]
        items[-1] = cast(
            BwItemResponse,
            {
                key: value
                for key, value in items[-1].items()
                if key not in {"organizationId", "collectionIds"}
            },
        )
        self.items = list(reversed(items)) if reverse else items
        self.writes: list[str] = []
        self.http = httpx.Client(
            base_url="http://localhost", transport=httpx.MockTransport(self.respond)
        )

    def respond(self, request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            raise AssertionError(f"Unexpected request method: {request.method}")
        # Deliberately return the union even for specific query parameters.
        return httpx.Response(200, json={"success": True, "data": {"data": self.items}})

    def get_item(self, item_id: str) -> BwItemResponse:
        return copy.deepcopy(next(item for item in self.items if item["id"] == item_id))

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        self.writes.append(item_id)
        self.items = [
            copy.deepcopy(item) if old["id"] == item_id else old for old in self.items
        ]

    def update_item_if_revision(
        self, item_id: str, item: BwItemResponse, *, expected_revision: str
    ) -> None:
        assert self.get_item(item_id)["revisionDate"] == expected_revision
        self.update_item(item_id, item)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.http.close()


def main() -> None:
    for reverse in (False, True):
        with ScopeClient(reverse=reverse) as client:
            assert len(client.list_items()) == 5
            assert {i["id"] for i in client.list_items(organization_id="org")} == {
                "inside",
                "outside",
            }
            assert {i["id"] for i in client.list_items(collection_id="inside")} == {
                "inside",
                "other-org",
            }
            assert client.list_items(folder_id="absent", organization_id="org") == []
            client.build_dedup_index()
            match = client.get_item_by_uuid("shared-source-uuid")
            assert match is not None and match["id"] == "inside"
            outside = copy.deepcopy(client.items)
            result = client.strip_field_from_items("KP2BW_ID", "KP2BW_SYNC")
            assert (result.scanned, result.stripped) == (1, 1)
            assert client.strip_field_from_items("KP2BW_ID", "KP2BW_SYNC").stripped == 0
            assert client.writes == ["inside"]
            assert [i for i in client.items if i["id"] != "inside"] == [
                i for i in outside if i["id"] != "inside"
            ]
        with ScopeClient(reverse=reverse) as client:
            outside = copy.deepcopy(client.items)
            client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)
            client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)
            assert client.writes == ["inside"]
            assert [i for i in client.items if i["id"] != "inside"] == [
                i for i in outside if i["id"] != "inside"
            ]
        with ScopeClient(reverse=reverse) as client:
            with (
                patch.object(cli, "BitwardenServeClient", return_value=client),
                patch.object(cli, "print_uri_report") as report,
            ):
                cli.run_report_uris_bitwarden(
                    bitwarden_password_arg="synthetic",
                    org_id="org",
                    collection_id="inside",
                )
            report.assert_called_once_with(["https://inside.example.test"], "bitwarden")
            assert not client.writes
    print("bw serve scope tests passed")


if __name__ == "__main__":
    main()
