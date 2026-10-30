"""Legacy upgrades preserve edits, unknown data, scope and rerun idempotency."""

import copy
import json
from unittest.mock import patch

from migrate_uris_test import _login, _MigrateClient

from kp2bw import cli
from kp2bw._fixups import FixupResult, run_fixups
from kp2bw._item_sync import stamp_content, sync_stamp_matches
from kp2bw.bw_serve import item_kp2bw_sync
from kp2bw.bw_types import BwItemResponse

YAML = "expires: '2040-01-01T00:00:00+00:00'\ntags:\n- b\n- a\n- 'café'\n"


def metadata(item_id: str, value: str = YAML) -> BwItemResponse:
    item = _login(item_id, [], "https://existing.example")
    item["fields"] = [{"name": "KP2BW_META", "value": value, "type": 0}]
    return item


def main() -> None:
    stamped = metadata("stamped")
    stamped["fields"].append({
        "name": "KP2A_URL",
        "value": "https://other.example",
        "type": 0,
    })
    stamp_content(stamped)
    modified = metadata("modified")
    stamp_content(modified)
    modified["notes"] = "preserve this edit"
    unstamped = metadata("unstamped")
    canonical = metadata("canonical", '{"tags": ["already JSON"]}')
    org = metadata("organization")
    org["organizationId"] = "org"
    org["collectionIds"] = ["inside"]
    outside = copy.deepcopy(org)
    outside["id"] = "outside"
    outside["collectionIds"] = ["outside"]
    bad = [
        metadata(f"bad-{i}", value)
        for i, value in enumerate((
            "tags: [unterminated",
            "tags: [yes]",
            "tags: [a]\ntags: [b]",
            "future: value",
            "tags: &tags [a]\nexpires: *tags",
            "!!python/object:unknown {tags: [a]}",
            "expires: 2040-01-01",
            "expires: 'not a timestamp'",
            "[]",
            "tags: " + "[" * 2000 + "a" + "]" * 2000,
        ))
    ]
    duplicate = metadata("duplicate")
    duplicate["fields"].append(copy.deepcopy(duplicate["fields"][0]))
    bad.append(duplicate)
    malformed_and_uri = metadata("atomic", "unknown: true")
    malformed_and_uri["fields"].append({
        "name": "KP2A_URL",
        "value": "https://must-remain.example",
        "type": 0,
    })
    bad.append(malformed_and_uri)
    hidden = _login("hidden", ["KP2A_URL"], "https://existing.example")
    hidden["fields"][0]["type"] = 1
    bad.append(hidden)
    items = [stamped, modified, unstamped, canonical, org, outside, *bad]
    original = copy.deepcopy(items)
    client = _MigrateClient(items)
    result = run_fixups(client)
    assert result == FixupResult(
        scanned=4 + len(bad), migrated=2, skipped=2, failed=len(bad)
    ), result
    assert client.updated_ids == ["stamped", "unstamped"]
    for item in client.updated_items.values():
        value = next(
            field["value"] for field in item["fields"] if field["name"] == "KP2BW_META"
        )
        assert value == json.dumps(
            {"expires": "2040-01-01T00:00:00+00:00", "tags": ["b", "a", "café"]},
            sort_keys=True,
        )
        stamp = item_kp2bw_sync(item)
        assert stamp and sync_stamp_matches(item, stamp)
    for before in original:
        if before["id"] not in client.updated_ids:
            assert client.get_item(before["id"]) == before
    client.updated_ids.clear()
    second = run_fixups(client)
    assert second.migrated == 0 and not client.updated_ids
    scoped = run_fixups(client, org_id="org", collection_id="inside")
    assert scoped == FixupResult(scanned=1, migrated=1)
    assert client.updated_ids == ["organization"]
    assert client.get_item("outside") == outside

    race = metadata("race")
    edited = copy.deepcopy(race)
    edited["notes"] = "concurrent edit"
    edited["revisionDate"] = "2026-09-05T00:00:05.000Z"
    for concurrent in (
        _MigrateClient([race], item_versions={"race": [race, edited]}),
        _MigrateClient([race], item_at_update={"race": edited}),
    ):
        result = run_fixups(concurrent)
        assert result.migrated == 0 and result.skipped + result.failed == 1
        assert not concurrent.updated_ids

    # The CLI must route fixup without a source database or KeePass prompt.
    with (
        patch.object(cli.sys, "argv", ["kp2bw", "--fixup", "-y"]),
        patch.object(cli, "_load_dotenv", return_value=None),
        patch.object(cli, "_configure_logging", return_value=None),
        patch.object(cli, "ensure_bw_available"),
        patch.object(
            cli, "_read_password", side_effect=AssertionError("unexpected prompt")
        ),
        patch.object(cli, "_run_fixup") as runner,
    ):
        cli.main()
        runner.assert_called_once()
    print("registered fixups, scope, edit protection and idempotency tests passed")


if __name__ == "__main__":
    main()
