"""Checks the Bitwarden-only URL-field -> URI upgrade pass (`--migrate-uris`).

`BitwardenServeClient.migrate_url_fields_to_uris` re-folds legacy KP2A_URL*/
AndroidApp custom fields into login URIs on existing items, skips non-login
items and items without such fields, and only PUTs the ones that change. Driven
with a client double, so no live `bw serve` process is spawned.
"""

from typing import Self, cast
from unittest import mock

from kp2bw import cli
from kp2bw._item_sync import content_signature, stamp_content
from kp2bw.bw_serve import (
    KP2BW_SYNC_FIELD_NAME,
    BitwardenServeClient,
    MigrateResult,
    item_kp2bw_sync,
)
from kp2bw.bw_types import BwField, BwItemResponse, BwUri
from kp2bw.uri_mapping import UriMatchValue, is_url_attribute_key


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
        fields = [f.get("name") or "" for f in item.get("fields") or []]
        if any(is_url_attribute_key(name) for name in fields):
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
    if result.protected != 0:
        raise AssertionError(f"expected 0 protected, got {result.protected}")
    if client.updated_ids != ["legacy"]:
        raise AssertionError(f"only the legacy item should PUT: {client.updated_ids}")
    if item_kp2bw_sync(legacy) != content_signature(legacy):
        raise AssertionError("unstamped legacy item did not receive a valid sync stamp")

    second = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)
    if (
        second.migrated != 0
        or second.protected != 0
        or client.updated_ids != ["legacy"]
    ):
        raise AssertionError("repeated migration should issue no additional PUT")


def assert_valid_stamp_is_refreshed() -> None:
    legacy = _login("stamped", ["KP2A_URL"], "https://legacy.example")
    stamp_content(legacy)
    old_stamp = item_kp2bw_sync(legacy)
    client = _MigrateClient([legacy])

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    new_stamp = item_kp2bw_sync(legacy)
    if result.migrated != 1 or client.updated_ids != ["stamped"]:
        raise AssertionError("untouched stamped item should migrate")
    if new_stamp == old_stamp or new_stamp != content_signature(legacy):
        raise AssertionError("migrated item did not receive its new content signature")


def assert_modified_stamped_item_is_preserved() -> None:
    legacy = _login("modified", ["KP2A_URL"], "https://legacy.example")
    stamp_content(legacy)
    old_stamp = item_kp2bw_sync(legacy)
    legacy["notes"] = "manual Bitwarden edit"
    client = _MigrateClient([legacy])

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    field_names = [field["name"] for field in legacy["fields"]]
    if result.migrated != 0 or result.protected != 1 or client.updated_ids:
        raise AssertionError("modified stamped item should not be PUT")
    if "KP2A_URL" not in field_names:
        raise AssertionError("modified item's legacy field should remain untouched")
    if item_kp2bw_sync(legacy) != old_stamp:
        raise AssertionError(f"{KP2BW_SYNC_FIELD_NAME} changed on skipped item")


def assert_cli_reports_protected_items() -> None:
    class _ResultClient:
        def __init__(self, result: MigrateResult) -> None:
            self._result = result

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def migrate_url_fields_to_uris(
            self, *, plain_match: UriMatchValue, interpret_syntax: bool
        ) -> MigrateResult:
            return self._result

    def _output(result: MigrateResult) -> str:
        def _make_client(*_args: object, **_kwargs: object) -> _ResultClient:
            return _ResultClient(result)

        with (
            mock.patch.object(cli, "BitwardenServeClient", _make_client),
            cli.console.capture() as capture,
        ):
            cli._run_migrate_uris(
                bitwarden_password_arg="bw-pw",
                org_id=None,
                collection_id=None,
                skip_confirm=True,
                uri_match=0,
                interpret_uri_syntax=True,
            )
        return capture.get()

    protected_only = _output(MigrateResult(scanned=3, migrated=0, protected=2))
    if "Preserved 2 item(s) modified in Bitwarden" not in protected_only:
        raise AssertionError("protected-only result was not reported")
    if "No items carried legacy URL fields" in protected_only:
        raise AssertionError("protected-only result was falsely reported as no-op")

    mixed = _output(MigrateResult(scanned=3, migrated=1, protected=1))
    if "Migrated URL fields to URIs on 1 of 3 item(s)" not in mixed:
        raise AssertionError("mixed result omitted migrated count")
    if "Preserved 1 item(s) modified in Bitwarden" not in mixed:
        raise AssertionError("mixed result omitted protected count")


def main() -> None:
    assert_only_login_items_with_legacy_fields_migrate()
    assert_valid_stamp_is_refreshed()
    assert_modified_stamped_item_is_preserved()
    assert_cli_reports_protected_items()
    print("migrate uris test passed")


if __name__ == "__main__":
    main()
