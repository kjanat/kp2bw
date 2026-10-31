from types import TracebackType
from typing import ClassVar, Self, cast
from unittest.mock import patch

import httpx

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemCreate, BwItemResponse
from kp2bw.convert import Converter
from kp2bw.item_sync import stamp_content

PERSONAL = "11111111-1111-4111-8111-111111111111"
INSIDE = "22222222-2222-4222-8222-222222222222"
OUTSIDE = "33333333-3333-4333-8333-333333333333"
SOURCES = {PERSONAL: "A" * 32, INSIDE: "B" * 32, OUTSIDE: "C" * 32}


def stamped(
    item_id: str, source: str, org: str | None, collections: list[str]
) -> BwItemResponse:
    item = cast(
        BwItemResponse,
        {
            "id": item_id,
            "name": item_id,
            "type": 1,
            "organizationId": org,
            "collectionIds": collections,
            "folderId": "folder-id",
            "fields": [{"name": "KP2BW_ID", "value": source, "type": 0}],
            "login": {"username": "u", "password": "p", "uris": []},
        },
    )
    stamp_content(item)
    return item


class ScopeClient(BitwardenServeClient):
    def __init__(self) -> None:
        self.organization_id = None
        self.collection_id = None
        self.collections = None
        self.folder_cache = {"stale": "stale-id"}
        self.by_uuid = {}
        self.legacy_by_folder_name = {}
        self.inventory_needs_check = False
        self.inventory_cache = None
        self.closed = False
        self.serve_process = None
        self.requests: list[str] = []
        self.rows: dict[str, list[object]] = {
            "folders": [{"id": "folder-id", "name": "Folder"}],
            "items": [
                stamped(PERSONAL, SOURCES[PERSONAL], None, []),
                stamped(INSIDE, SOURCES[INSIDE], "org", ["inside"]),
                stamped(OUTSIDE, SOURCES[OUTSIDE], "org", ["outside"]),
            ],
            "org-collections": [
                {"id": "inside", "name": "Inside"},
                {"id": "outside", "name": "Outside"},
            ],
        }
        self.http = httpx.Client(
            base_url="http://localhost", transport=httpx.MockTransport(self.respond)
        )

    def respond(self, request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            raise AssertionError(f"Unexpected {request.method} {request.url.path}")
        self.requests.append(request.url.path)
        kind = request.url.path.removeprefix("/list/object/")
        return httpx.Response(
            200, json={"success": True, "data": {"data": self.rows[kind]}}
        )

    def close(self) -> None:
        raise AssertionError("A caller-owned client must stay open")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        raise AssertionError("A caller-owned client must not be exited")

    def __enter__(self) -> Self:
        raise AssertionError("A caller-owned client must not be entered")


def converter(
    org: str | None = None, collection: str | None = None, **selection: str
) -> Converter:
    return Converter(
        "unused.kdbx",
        "pw",
        None,
        "pw",
        org,
        collection,
        False,
        1,
        None,
        entry_id=selection.get("entry_id"),
        item_id=selection.get("item_id"),
    )


def check_scope_reloads_and_restores() -> None:
    client = ScopeClient()
    with client.scope("org", "inside") as scoped:
        assert scoped is client
        assert (client.organization_id, client.collection_id) == ("org", "inside")
        assert client.folder_cache == {"Folder": "folder-id"}
        assert set(client.by_uuid) == {SOURCES[INSIDE]}
        assert client.collections == {"Inside": "inside", "Outside": "outside"}
    assert (client.organization_id, client.collection_id) == (None, None)
    assert client.collections is None
    assert client.folder_cache == {"stale": "stale-id"}
    assert client.by_uuid == {}
    try:
        with client.scope("org", None):
            assert set(client.by_uuid) == {SOURCES[INSIDE], SOURCES[OUTSIDE]}
            raise RuntimeError("abort inside scope")
    except RuntimeError:
        pass
    assert (client.organization_id, client.collection_id) == (None, None)
    assert client.by_uuid == {}


def check_convert_reuses_client(
    org: str | None,
    collection: str | None,
    expected_scope: tuple[str | None, str | None],
    expected_index: set[str],
) -> None:
    client = ScopeClient()
    conv = converter(org, collection)
    observed: list[tuple[tuple[str | None, str | None], set[str]]] = []

    def write(bw: BitwardenServeClient | None = None) -> int:
        assert bw is not None and bw is client
        observed.append(((bw.organization_id, bw.collection_id), set(bw.by_uuid)))
        return 3

    with (
        patch.object(conv, "prepare_entries"),
        patch.object(conv, "create_bitwarden_items_for_entries", side_effect=write),
        patch(
            "kp2bw.convert.BitwardenServeClient",
            side_effect=AssertionError("convert opened a second client"),
        ),
    ):
        assert conv.convert(client) == 3
    assert observed == [(expected_scope, expected_index)]
    assert (client.organization_id, client.collection_id) == (None, None)


def selected_item() -> BwItemCreate:
    return BwItemCreate(
        name="inside",
        type=1,
        organizationId=None,
        collectionIds=[],
        folderId=None,
        notes=None,
        favorite=False,
        fields=[],
        secureNote=None,
        card=None,
        identity=None,
        login={
            "username": "u",
            "password": "p",
            "uris": [],
            "totp": None,
            "passwordRevisionDate": None,
        },
    )


class OwnedClient(ScopeClient):
    opened: ClassVar[list[tuple[str, str | None, str | None]]] = []
    exited: ClassVar[list[bool]] = []

    def __init__(
        self, password: str, *, org_id: str | None, collection_id: str | None
    ) -> None:
        super().__init__()
        self.opened.append((password, org_id, collection_id))

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.exited.append(True)


def check_selected_convert(owned: bool) -> None:
    client = ScopeClient()
    conv = converter(item_id=INSIDE)
    seen: list[BitwardenServeClient | None] = []

    def prepare() -> None:
        conv.entries = {SOURCES[INSIDE]: (None, None, selected_item(), [])}

    def write(bw: BitwardenServeClient | None = None) -> int:
        seen.append(bw)
        return 0

    OwnedClient.opened.clear()
    OwnedClient.exited.clear()
    with (
        patch.object(conv, "prepare_entries", side_effect=prepare),
        patch.object(conv, "create_bitwarden_items_for_entries", side_effect=write),
        patch("kp2bw.convert.BitwardenServeClient", OwnedClient),
    ):
        assert (conv.convert() if owned else conv.convert(client)) == 0
    assert len(seen) == 1
    if owned:
        assert isinstance(seen[0], OwnedClient)
        assert OwnedClient.opened == [("pw", None, None)]
        assert OwnedClient.exited == [True]
    else:
        assert seen == [client]
        assert OwnedClient.opened == []
    assert conv.selection is not None
    assert conv.selection.destination_id == INSIDE
    assert conv.selection.source_id == SOURCES[INSIDE]


def check_unselected_convert_without_client_owns_one() -> None:
    conv = converter("org", "inside")
    seen: list[BitwardenServeClient | None] = []

    def write(bw: BitwardenServeClient | None = None) -> int:
        seen.append(bw)
        return 0

    with (
        patch.object(conv, "prepare_entries"),
        patch.object(conv, "create_bitwarden_items_for_entries", side_effect=write),
    ):
        assert conv.convert() == 0
    assert seen == [None]


def main() -> None:
    check_scope_reloads_and_restores()
    check_convert_reuses_client(None, None, (None, None), set(SOURCES.values()))
    check_convert_reuses_client("org", "inside", ("org", "inside"), {SOURCES[INSIDE]})
    check_convert_reuses_client(
        "org", "auto", ("org", None), {SOURCES[INSIDE], SOURCES[OUTSIDE]}
    )
    check_selected_convert(owned=False)
    check_selected_convert(owned=True)
    check_unselected_convert_without_client_owns_one()
    print("convert client reuse test passed")


if __name__ == "__main__":
    main()
