"""Checks the Bitwarden-only URL-field -> URI upgrade pass (`--migrate-uris`).

`BitwardenServeClient.migrate_url_fields_to_uris` re-folds legacy KP2A_URL*/
AndroidApp custom fields into login URIs on existing items, skips non-login
items and items without such fields, and only PUTs the ones that change. Driven
with a client double, so no live `bw serve` process is spawned.
"""

import copy
from datetime import datetime
from typing import Self, cast
from unittest import mock

from kp2bw import cli
from kp2bw._item_sync import (
    content_signature,
    legacy_content_signature,
    stamp_content,
)
from kp2bw.bw_serve import (
    KP2BW_SYNC_FIELD_NAME,
    BitwardenServeClient,
    MigrateResult,
    item_kp2bw_sync,
)
from kp2bw.bw_types import BwField, BwItemResponse, BwUri
from kp2bw.exceptions import BitwardenHttpError
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
            "object": "item",
            "revisionDate": "2026-09-05T00:00:00.000Z",
            "name": item_id,
            "type": 1,
            "fields": fields,
            "login": {"uris": [cast(BwUri, {"uri": uri, "match": 0})]},
        },
    )


class _MigrateClient(BitwardenServeClient):
    """Client double serving a fixed item list and recording every PUT."""

    def __init__(
        self,
        items: list[BwItemResponse],
        *,
        current_items: list[BwItemResponse] | None = None,
        item_versions: dict[str, list[BwItemResponse]] | None = None,
        item_at_update: dict[str, BwItemResponse] | None = None,
        commit_then_conflict: set[str] | None = None,
        update_errors: dict[str, BitwardenHttpError] | None = None,
    ) -> None:
        self._org_id = None
        self._collection_id = None
        self._items = items
        current = items if current_items is None else current_items
        self._current_by_id = {item["id"]: item for item in current}
        self._item_versions = item_versions or {}
        self._item_at_update = item_at_update or {}
        self._commit_then_conflict = commit_then_conflict or set()
        self._update_errors = update_errors or {}
        self.updated_ids: list[str] = []
        self.updated_items: dict[str, BwItemResponse] = {}
        self.expected_revisions: list[str] = []

    def list_items(
        self,
        *,
        folder_id: str | None = None,
        organization_id: str | None = None,
        collection_id: str | None = None,
    ) -> list[BwItemResponse]:
        return self._items

    def get_item(self, item_id: str) -> BwItemResponse:
        versions = self._item_versions.get(item_id)
        if versions:
            item = versions.pop(0) if len(versions) > 1 else versions[0]
            return copy.deepcopy(item)
        return copy.deepcopy(self._current_by_id[item_id])

    def sync(self) -> None:
        pass

    def update_item_if_revision(
        self, item_id: str, item: BwItemResponse, *, expected_revision: str
    ) -> None:
        self.expected_revisions.append(expected_revision)
        if item_id in self._commit_then_conflict:
            committed = copy.deepcopy(item)
            committed["revisionDate"] = "2026-09-05T00:00:02.000Z"
            self._current_by_id[item_id] = committed
            self.updated_ids.append(item_id)
            self.updated_items[item_id] = committed
            raise BitwardenHttpError("conflict", status_code=400)
        concurrent = self._item_at_update.get(item_id)
        if concurrent is not None:
            self._current_by_id[item_id] = concurrent
        update_error = self._update_errors.get(item_id)
        if update_error is not None:
            raise update_error
        current_revision = self._current_by_id[item_id]["revisionDate"]
        revision_gap = abs(
            (
                datetime.fromisoformat(current_revision)
                - datetime.fromisoformat(expected_revision)
            ).total_seconds()
        )
        if revision_gap > 1:
            raise BitwardenHttpError("conflict", status_code=400)
        self.updated_ids.append(item_id)
        self.updated_items[item_id] = item
        self._current_by_id[item_id] = item
        self._items = [
            item if listed["id"] == item_id else listed for listed in self._items
        ]
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
    updated = client.updated_items["legacy"]
    if item_kp2bw_sync(updated) != content_signature(updated):
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

    updated = client.updated_items["stamped"]
    new_stamp = item_kp2bw_sync(updated)
    if result.migrated != 1 or client.updated_ids != ["stamped"]:
        raise AssertionError("untouched stamped item should migrate")
    if new_stamp == old_stamp or new_stamp != content_signature(updated):
        raise AssertionError("migrated item did not receive its new content signature")


def assert_unambiguous_legacy_stamp_is_upgraded() -> None:
    legacy = _login("safe-old-stamp", ["KP2A_URL"], "")
    login = legacy.get("login")
    if login is None:
        raise AssertionError("legacy test item must be a login")
    login["uris"] = []
    legacy["fields"].append(
        cast(
            BwField,
            {
                "name": KP2BW_SYNC_FIELD_NAME,
                "value": legacy_content_signature(legacy),
                "type": 0,
            },
        )
    )
    client = _MigrateClient([legacy])

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    updated = client.updated_items["safe-old-stamp"]
    if result.migrated != 1 or item_kp2bw_sync(updated) != content_signature(updated):
        raise AssertionError("unambiguous legacy sync stamp was not upgraded")


def assert_legacy_stamp_is_preserved_as_ambiguous() -> None:
    legacy = _login("old-stamp", ["KP2A_URL"], "https://legacy.example")
    legacy["fields"].append(
        cast(
            BwField,
            {"name": "linked", "value": "", "type": 3, "linkedId": 100},
        )
    )
    legacy["fields"].append(
        cast(
            BwField,
            {
                "name": KP2BW_SYNC_FIELD_NAME,
                "value": legacy_content_signature(legacy),
                "type": 0,
            },
        )
    )
    login = legacy.get("login")
    if login is None:
        raise AssertionError("legacy test item must be a login")
    login["uris"][0]["match"] = 1
    legacy["fields"][-2]["linkedId"] = 101
    client = _MigrateClient([legacy])

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    if result.migrated != 0 or result.protected != 1 or client.updated_ids:
        raise AssertionError("legacy-only sync stamp must fail closed")
    if not any(field["name"] == "KP2A_URL" for field in legacy["fields"]):
        raise AssertionError("ambiguous legacy-stamped item was transformed")


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


def assert_fresh_item_is_used_instead_of_list_snapshot() -> None:
    listed = _login("stale-list", ["KP2A_URL"], "https://legacy.example")
    stamp_content(listed)
    current = copy.deepcopy(listed)
    current["notes"] = "concurrent Bitwarden edit"
    client = _MigrateClient([listed], current_items=[current])

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    if result.migrated != 0 or result.protected != 1 or client.updated_ids:
        raise AssertionError("stale list snapshot overwrote the freshly fetched item")
    if not any(field["name"] == "KP2A_URL" for field in current["fields"]):
        raise AssertionError("freshly fetched item was mutated despite its stale stamp")


def assert_change_during_migration_is_preserved() -> None:
    listed = _login("racing", ["KP2A_URL"], "https://legacy.example")
    stamp_content(listed)
    concurrent = copy.deepcopy(listed)
    concurrent["notes"] = "edit after validation"
    client = _MigrateClient([listed], item_versions={"racing": [listed, concurrent]})

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    if result.migrated != 0 or result.protected != 1 or client.updated_ids:
        raise AssertionError("an item changed during migration should not be PUT")


def assert_loginless_candidate_is_reported_as_protected() -> None:
    item = _login("loginless", ["KP2A_URL"], "https://legacy.example")
    del item["login"]
    client = _MigrateClient([item])

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    if result.migrated != 0 or result.protected != 1 or client.updated_ids:
        raise AssertionError("login-less candidate should be reported as protected")


def assert_change_after_final_read_is_preserved() -> None:
    listed = _login("late-race", ["KP2A_URL"], "https://legacy.example")
    stamp_content(listed)
    concurrent = copy.deepcopy(listed)
    concurrent["notes"] = "edit after final read"
    concurrent["revisionDate"] = "2026-09-05T00:00:02.000Z"
    client = _MigrateClient([listed], item_at_update={"late-race": concurrent})

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    if result.migrated != 0 or result.protected != 1 or client.updated_ids:
        raise AssertionError("a post-read revision conflict should not be overwritten")
    if client._current_by_id["late-race"].get("notes") != "edit after final read":
        raise AssertionError("the post-read concurrent edit was not preserved")


def assert_committed_retry_conflict_is_reported_as_migrated() -> None:
    listed = _login("committed", ["KP2A_URL"], "https://legacy.example")
    stamp_content(listed)
    client = _MigrateClient([listed], commit_then_conflict={"committed"})

    result = client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)

    if result.migrated != 1 or result.protected != 0:
        raise AssertionError("a committed retry conflict was misreported")
    updated = client._current_by_id["committed"]
    if any(
        is_url_attribute_key(field.get("name") or "")
        for field in (updated.get("fields") or [])
    ):
        raise AssertionError("the committed update did not migrate its URL fields")


def assert_same_revision_http_error_is_not_a_conflict() -> None:
    listed = _login("invalid", ["KP2A_URL"], "https://legacy.example")
    stamp_content(listed)
    error = BitwardenHttpError("validation failed", status_code=400)
    client = _MigrateClient([listed], update_errors={"invalid": error})

    try:
        client.migrate_url_fields_to_uris(plain_match=0, interpret_syntax=True)
    except BitwardenHttpError as exc:
        if exc is not error:
            raise AssertionError("migration raised the wrong HTTP failure") from None
        return
    raise AssertionError("same-revision HTTP failure was misclassified as a conflict")


def assert_conditional_update_body_carries_revision() -> None:
    item = _login("conditional", ["KP2A_URL"], "https://legacy.example")
    plain = BitwardenServeClient._item_update_body(item)
    conditional = BitwardenServeClient._item_update_body(
        item, expected_revision=item["revisionDate"]
    )

    if "revisionDate" in plain:
        raise AssertionError("ordinary update body unexpectedly carried a revision")
    if conditional.get("revisionDate") != item["revisionDate"]:
        raise AssertionError("conditional update body omitted the observed revision")


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
    if "Preserved 2 item(s) that could not be updated safely" not in protected_only:
        raise AssertionError("protected-only result was not reported")
    if "No items carried legacy URL fields" in protected_only:
        raise AssertionError("protected-only result was falsely reported as no-op")

    mixed = _output(MigrateResult(scanned=3, migrated=1, protected=1))
    if "Migrated URL fields to URIs on 1 of 3 item(s)" not in mixed:
        raise AssertionError("mixed result omitted migrated count")
    if "Preserved 1 item(s) that could not be updated safely" not in mixed:
        raise AssertionError("mixed result omitted protected count")


def main() -> None:
    assert_only_login_items_with_legacy_fields_migrate()
    assert_valid_stamp_is_refreshed()
    assert_unambiguous_legacy_stamp_is_upgraded()
    assert_legacy_stamp_is_preserved_as_ambiguous()
    assert_modified_stamped_item_is_preserved()
    assert_fresh_item_is_used_instead_of_list_snapshot()
    assert_change_during_migration_is_preserved()
    assert_loginless_candidate_is_reported_as_protected()
    assert_change_after_final_read_is_preserved()
    assert_committed_retry_conflict_is_reported_as_migrated()
    assert_same_revision_http_error_is_not_a_conflict()
    assert_conditional_update_body_carries_revision()
    assert_cli_reports_protected_items()
    print("migrate uris test passed")


if __name__ == "__main__":
    main()
