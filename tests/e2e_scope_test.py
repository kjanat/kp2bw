"""Live #69 regression against the disposable Vaultwarden fixture only."""

from typing import cast

from e2e_support import Vault, vault_main
from pykeepass import create_database

from kp2bw.bw_types import BwItemCreate, BwItemResponse
from kp2bw.convert import Converter
from kp2bw.item_sync import (
    KP2BW_ID_FIELD_NAME,
    KP2BW_SYNC_FIELD_NAME,
    stamp_content,
)
from kp2bw.uri_mapping import parse_match_name


def run_scope_test(vault: Vault) -> None:
    password = vault.password
    org_id = vault.organization()
    inside = vault.collections(org_id)["Scope A"]
    bw = vault.client
    source = vault.tmp / "scope.kdbx"
    db = create_database(source, password="synthetic-keepass-password")
    entry = db.add_entry(db.root_group, "A imported", "source-user", "source-password")
    db.save()
    with bw.scope(org_id, inside):
        outside = bw.create_org_collection("Scope B")
    assert outside is not None
    ids: list[str] = []
    for name, collection in (("A original", inside), ("Z outside", outside)):
        item = cast(
            BwItemResponse,
            {
                "name": name,
                "type": 1,
                "organizationId": org_id,
                "collectionIds": [collection],
                "login": {"username": "old", "password": "old", "uris": []},
                "fields": [
                    {
                        "name": "KP2BW_ID",
                        "value": entry.uuid.hex.upper(),
                        "type": 0,
                    }
                ],
            },
        )
        stamp_content(item)
        ids.append(bw.create_item(cast(BwItemCreate, item)))

    def read_items() -> dict[str, BwItemResponse]:
        items = vault.fresh().list_items()
        for item in items:
            # Download URLs carry expiring tokens; compare persisted content.
            for attachment in item.get("attachments") or []:
                attachment.pop("url", None)
        return {item["id"]: item for item in items}

    def migrate_uris() -> None:
        with bw.scope(org_id, inside):
            bw.migrate_url_fields_to_uris(
                plain_match=parse_match_name("default"), interpret_syntax=True
            )

    def strip_ids() -> None:
        with bw.scope(org_id, inside):
            bw.strip_field_from_items(KP2BW_ID_FIELD_NAME, KP2BW_SYNC_FIELD_NAME)

    original = read_items()
    command = ["-o", org_id, "-c", inside, "-y"]
    import_command = [
        *command,
        str(source),
        "--keepass-password",
        "synthetic-keepass-password",
        "--path-to-name-skip",
        "999",
        "--no-metadata",
    ]
    env = {"KP2BW_BITWARDEN_PASSWORD": password}
    vault.kp2bw(*import_command, env=env)
    imported = read_items()
    assert imported[ids[0]]["name"] == "A imported"
    assert imported[ids[1]] == original[ids[1]], "Import changed the outside control"
    rerun = Converter(
        str(source),
        "synthetic-keepass-password",
        None,
        password,
        org_id,
        inside,
        False,
        999,
        None,
        migrate_metadata=False,
        create_folders=False,
    )
    assert rerun.convert(bw) == 0
    assert read_items() == imported, "Unchanged scoped import wrote an item"

    # Seed distinct reporting domains and legacy fields after import, then
    # exercise the actual maintenance CLI, with revision-sensitive controls.
    for item_id, domain in zip(
        ids, ("inside-scope.example", "outside-scope.example"), strict=True
    ):
        item = vault.fresh().get_item(item_id)
        item["fields"] = [
            *(item.get("fields") or []),
            {
                "name": "KP2A_URL",
                "value": f"https://legacy.{domain}",
                "type": 0,
            },
        ]
        login = item.get("login")
        assert login is not None
        login["uris"] = [
            {"uri": f"https://{host}.{domain}", "match": 0} for host in ("one", "two")
        ]
        stamp_content(item)
        bw.update_item(item_id, item)
    before = read_items()
    report = vault.kp2bw(*command, "--report-uris", "bitwarden", env=env).stdout
    assert "inside-scope.example" in report and "outside-scope.example" not in report
    assert read_items() == before, "Reporting changed vault content"
    migrate_uris()
    migrated = read_items()
    assert migrated[ids[1]] == before[ids[1]], (
        "URI migration changed the outside control"
    )
    assert not any(
        f.get("name") == "KP2A_URL" for f in migrated[ids[0]].get("fields") or []
    )
    migrate_uris()
    assert read_items() == migrated, "Repeated URI migration wrote an item"
    vault.kp2bw(*command, "--strip-ids", env=env)
    stripped = read_items()
    assert stripped[ids[1]] == before[ids[1]], (
        "Finalization changed the outside control"
    )
    assert not any(
        f.get("name") in {"KP2BW_ID", "KP2BW_SYNC"}
        for f in stripped[ids[0]].get("fields") or []
    )
    strip_ids()
    assert read_items() == stripped, "Repeated finalization wrote an item"
    print("live organization/collection scope regression passed")


def main() -> None:
    vault_main(run_scope_test)


if __name__ == "__main__":
    main()
