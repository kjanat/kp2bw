"""Live #69 regression against the disposable Vaultwarden fixture only."""

from dataclasses import dataclass
from pathlib import Path
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


@dataclass
class ScopeFixture:
    vault: Vault
    org_id: str
    inside: str
    ids: list[str]
    source: Path
    env: dict[str, str]

    @property
    def command(self) -> list[str]:
        return ["-o", self.org_id, "-c", self.inside, "-y"]

    def read_items(self) -> dict[str, BwItemResponse]:
        items = self.vault.fresh().list_items()
        for item in items:
            # Download URLs carry expiring tokens; compare persisted content.
            for attachment in item.get("attachments") or []:
                attachment.pop("url", None)
        return {item["id"]: item for item in items}

    def seed(self) -> dict[str, BwItemResponse]:
        # Seed distinct reporting domains and legacy fields, then exercise the
        # actual maintenance CLI, with revision-sensitive controls.
        bw = self.vault.client
        for item_id, domain in zip(
            self.ids, ("inside-scope.example", "outside-scope.example"), strict=True
        ):
            item = self.vault.fresh().get_item(item_id)
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
                {"uri": f"https://{host}.{domain}", "match": 0}
                for host in ("one", "two")
            ]
            stamp_content(item)
            bw.update_item(item_id, item)
        return self.read_items()


def scope_fixture(vault: Vault, name: str) -> ScopeFixture:
    org_id = vault.organization()
    inside = vault.collections(org_id)["Scope A"]
    bw = vault.client
    source = vault.tmp / f"{name}.kdbx"
    db = create_database(source, password="synthetic-keepass-password")
    entry = db.add_entry(db.root_group, "A imported", "source-user", "source-password")
    db.save()
    with bw.scope(org_id, inside):
        outside = bw.create_org_collection("Scope B")
    assert outside is not None
    ids: list[str] = []
    for item_name, collection in (("A original", inside), ("Z outside", outside)):
        item = cast(
            BwItemResponse,
            {
                "name": item_name,
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
    return ScopeFixture(
        vault, org_id, inside, ids, source, {"KP2BW_BITWARDEN_PASSWORD": vault.password}
    )


def run_scope_test(vault: Vault) -> None:
    fixture = scope_fixture(vault, "scope-import")
    ids = fixture.ids
    original = fixture.read_items()
    vault.kp2bw(
        *fixture.command,
        str(fixture.source),
        "--keepass-password",
        "synthetic-keepass-password",
        "--path-to-name-skip",
        "999",
        "--no-metadata",
        env=fixture.env,
    )
    imported = fixture.read_items()
    assert imported[ids[0]]["name"] == "A imported"
    assert imported[ids[1]] == original[ids[1]], "Import changed the outside control"
    rerun = Converter(
        str(fixture.source),
        "synthetic-keepass-password",
        None,
        vault.password,
        fixture.org_id,
        fixture.inside,
        False,
        999,
        None,
        migrate_metadata=False,
        create_folders=False,
    )
    assert rerun.convert(vault.client) == 0
    assert fixture.read_items() == imported, "Unchanged scoped import wrote an item"
    print("live organization/collection scoped import passed")


def run_scope_report_test(vault: Vault) -> None:
    fixture = scope_fixture(vault, "scope-report")
    before = fixture.seed()
    report = vault.kp2bw(
        *fixture.command, "--report-uris", "bitwarden", env=fixture.env
    ).stdout
    assert "inside-scope.example" in report and "outside-scope.example" not in report
    assert fixture.read_items() == before, "Reporting changed vault content"
    print("live organization/collection URI report passed")


def run_scope_migrate_uris_test(vault: Vault) -> None:
    fixture = scope_fixture(vault, "scope-migrate-uris")
    ids = fixture.ids
    before = fixture.seed()
    vault.kp2bw(*fixture.command, "--migrate-uris", env=fixture.env)
    migrated = fixture.read_items()
    assert migrated[ids[1]] == before[ids[1]], (
        "URI migration changed the outside control"
    )
    assert not any(
        f.get("name") == "KP2A_URL" for f in migrated[ids[0]].get("fields") or []
    )
    bw = vault.client
    with bw.scope(fixture.org_id, fixture.inside):
        bw.migrate_url_fields_to_uris(
            plain_match=parse_match_name("default"), interpret_syntax=True
        )
    assert fixture.read_items() == migrated, "Repeated URI migration wrote an item"
    print("live organization/collection URI migration passed")


def run_scope_strip_test(vault: Vault) -> None:
    fixture = scope_fixture(vault, "scope-strip")
    ids = fixture.ids
    before = fixture.seed()
    vault.kp2bw(*fixture.command, "--strip-ids", env=fixture.env)
    stripped = fixture.read_items()
    assert stripped[ids[1]] == before[ids[1]], (
        "Finalization changed the outside control"
    )
    assert not any(
        f.get("name") in {"KP2BW_ID", "KP2BW_SYNC"}
        for f in stripped[ids[0]].get("fields") or []
    )
    bw = vault.client
    with bw.scope(fixture.org_id, fixture.inside):
        bw.strip_field_from_items(KP2BW_ID_FIELD_NAME, KP2BW_SYNC_FIELD_NAME)
    assert fixture.read_items() == stripped, "Repeated finalization wrote an item"
    print("live organization/collection finalization passed")


def main() -> None:
    def run_all(vault: Vault) -> None:
        run_scope_test(vault)
        run_scope_report_test(vault)
        run_scope_migrate_uris_test(vault)
        run_scope_strip_test(vault)

    vault_main(run_all)


if __name__ == "__main__":
    main()
