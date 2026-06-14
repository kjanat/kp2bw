"""Checks the Bitwarden-only URL-field -> URI upgrade pass (`--migrate-uris`).

`BitwardenServeClient.migrate_url_fields_to_uris` re-folds legacy KP2A_URL*/
AndroidApp custom fields into login URIs on existing items, skips non-login
items and items without such fields, and only PUTs the ones that change. Driven
with a client double, so no live `bw serve` process is spawned.
"""

from typing import cast

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwField, BwItemResponse, BwUri


def _login(item_id: str, field_names: list[str], uri: str) -> BwItemResponse:
    fields = [
        cast(BwField, {"name": n, "value": "https://v.example", "type": 0})
        for n in field_names
    ]
    return cast(
        BwItemResponse,
        {
            "id": item_id,
            "name": item_id,
            "type": 1,
            "fields": fields,
            "login": {"uris": [cast(BwUri, {"uri": uri, "match": 0})]},
        },
    )


class _MigrateClient(BitwardenServeClient):
    """Client double serving a fixed item list and recording every PUT."""

    def __init__(self, items: list[BwItemResponse]) -> None:
        self._org_id = None
        self._collection_id = None
        self._items = items
        self.updated_ids: list[str] = []

    def list_items(
        self,
        *,
        folder_id: str | None = None,
        organization_id: str | None = None,
        collection_id: str | None = None,
    ) -> list[BwItemResponse]:
        return self._items

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        self.updated_ids.append(item_id)
        fields = [f.get("name", "") for f in item.get("fields") or []]
        if any(name.startswith(("KP2A_URL", "URL", "AndroidApp")) for name in fields):
            raise AssertionError(f"{item_id} still carries a legacy URL/app field")


def assert_only_login_items_with_legacy_fields_migrate() -> None:
    legacy = _login("legacy", ["Notes", "KP2A_URL"], "https://legacy.example")
    clean = _login("clean", ["Notes"], "https://clean.example")
    non_login = cast(
        BwItemResponse,
        {"id": "note", "name": "note", "type": 2, "fields": [], "login": None},
    )
    client = _MigrateClient([legacy, clean, non_login])

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    if result.scanned != 3:
        raise AssertionError(f"expected 3 scanned, got {result.scanned}")
    if result.migrated != 1:
        raise AssertionError(f"expected 1 migrated, got {result.migrated}")
    if client.updated_ids != ["legacy"]:
        raise AssertionError(f"only the legacy item should PUT: {client.updated_ids}")


def main() -> None:
    assert_only_login_items_with_legacy_fields_migrate()
    print("migrate uris test passed")


if __name__ == "__main__":
    main()
