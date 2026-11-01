"""Native templates survive real CLI creation, updates and unchanged reruns."""

import copy
import json
from dataclasses import dataclass
from pathlib import Path

from e2e_support import Vault, vault_main
from pykeepass import Entry, PyKeePass, create_database

from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.item_sync import pre_history_content_signature
from kp2bw.templates import parse_template_overrides


@dataclass
class TemplateFixture:
    vault: Vault
    source: Path
    db: PyKeePass
    sources: dict[str, Entry]
    mapping: Path
    env: dict[str, str]

    def converter(
        self, entry_id: str | None = None, item_id: str | None = None
    ) -> Converter:
        return Converter(
            str(self.source),
            "synthetic",
            None,
            self.vault.password,
            None,
            None,
            False,
            999,
            None,
            migrate_metadata=False,
            map_templates=True,
            template_map=parse_template_overrides(
                json.loads(self.mapping.read_text(encoding="utf-8"))
            ),
            entry_id=entry_id,
            item_id=item_id,
        )

    def migrate(self) -> None:
        assert self.converter().convert(self.vault.client) == 0

    def read(self) -> dict[str, BwItemResponse]:
        return {
            title: self.vault.item(entry.uuid.hex.upper())
            for title, entry in self.sources.items()
        }


def template_fixture(vault: Vault, name: str) -> TemplateFixture:
    tmp = vault.tmp / name
    tmp.mkdir()
    source = tmp / "templates.kdbx"
    db = create_database(source, password="synthetic")
    sources: dict[str, Entry] = {}
    for title in ("Credit Card", "Identity", "Secure Note"):
        template = db.add_entry(db.root_group, title, "", "")
        template.set_custom_property("_etm_template", "1")
        item = db.add_entry(db.root_group, "Native " + title, "", "")
        item.set_custom_property("_etm_template_uuid", template.uuid.hex)
        item.set_custom_property("KP2BW_HISTORY", "ordinary source value")
        sources[title] = item
    card = sources["Credit Card"]
    card.set_custom_property("Number", "4111 1111 1111 1111")
    card.set_custom_property("CVV", "123", protect=True)
    card.set_custom_property("PIN", "4321", protect=True)
    card.set_custom_property("Expiry", "03/29")
    sources["Identity"].set_custom_property("First Name", "Ada")
    sources["Identity"].set_custom_property("Last Name", "Example")
    sources["Secure Note"].notes = "A native secure note"
    alias = db.add_entry(
        db.root_group,
        "Native target alias",
        "",
        f"{{REF:P@I:{card.uuid.hex.upper()}}}",
    )
    alias.url = "https://native-alias.example.test"
    alias.otp = "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP"
    sources["Alias"] = alias
    identity_source = sources["Identity"]
    identity_source.set_custom_property("KP2BW_ID", "source-username")
    mapping = tmp / "template-map.json"
    mapping.write_text(
        json.dumps({
            identity_source.get_custom_property("_etm_template_uuid"): {
                "type": "identity",
                "fields": {"KP2BW_ID": "username"},
            }
        }),
        encoding="utf-8",
    )
    conflict = db.add_entry(db.root_group, "Conflicting Card", "", "")
    conflict.set_custom_property(
        "_etm_template_uuid", card.get_custom_property("_etm_template_uuid") or ""
    )
    conflict.set_custom_property("Number", "4111111111111111")
    sources["Conflicting Card"] = conflict
    number_node = conflict._element.find("./String[Key='Number']")
    assert number_node is not None
    duplicate_node = copy.deepcopy(number_node)
    number_value = duplicate_node.find("Value")
    assert number_value is not None
    number_value.text = "5555555555554444"
    conflict._element.append(duplicate_node)
    env = {"KP2BW_MAP_TEMPLATES": "true", "KP2BW_TEMPLATE_MAP": str(mapping)}
    db.save()
    return TemplateFixture(vault, source, db, sources, mapping, env)


def check_initial(fixture: TemplateFixture, initial: dict[str, BwItemResponse]) -> None:
    sources = fixture.sources
    identity_source = sources["Identity"]
    alias = sources["Alias"]
    assert [initial[key]["type"] for key in sources] == [3, 4, 2, 1, 3]
    conflict_card = initial["Conflicting Card"]["card"]
    assert conflict_card is not None and not conflict_card.get("number")
    assert {
        field["value"]
        for field in initial["Conflicting Card"]["fields"]
        if "Number" in field["name"]
    } == {"4111111111111111", "5555555555554444"}
    native_card = initial["Credit Card"]["card"]
    assert native_card is not None and native_card.get("number") == "4111111111111111"
    assert native_card.get("expMonth") == "3" and native_card.get("expYear") == "2029"
    assert any(
        f["name"] == "PIN" and f["value"] == "4321" and f["type"] == 1
        for f in initial["Credit Card"]["fields"]
    )
    identity = initial["Identity"]["identity"]
    assert identity is not None and identity.get("firstName") == "Ada"
    assert identity.get("username") == "source-username"
    assert any(
        field["name"] == "KP2BW_ID"
        and field["value"] == identity_source.uuid.hex.upper()
        for field in initial["Identity"]["fields"]
    )
    alias_login = initial["Alias"].get("login")
    assert alias_login is not None and alias_login.get("totp")
    assert any(uri["uri"] == alias.url for uri in alias_login.get("uris") or [])
    assert initial["Secure Note"]["notes"] == "A native secure note"


def run_templates_cli_test(vault: Vault) -> None:
    fixture = template_fixture(vault, "templates-cli")
    vault.migrate(fixture.source, "synthetic", env=fixture.env)
    check_initial(fixture, fixture.read())
    print("native template CLI import passed")


def run_templates_test(vault: Vault) -> None:
    fixture = template_fixture(vault, "templates")
    bw = vault.client
    migrate = fixture.migrate
    read = fixture.read
    migrate()
    initial = read()
    check_initial(fixture, initial)
    # Reproduce pre-history native imports with an ordinary marker-name field.
    for title in ("Credit Card", "Identity", "Secure Note"):
        legacy = copy.deepcopy(initial[title])
        for field in legacy["fields"]:
            if field["name"] == "KeePass:KP2BW_HISTORY:1":
                field["name"] = "KP2BW_HISTORY"
        stamp = pre_history_content_signature(legacy)
        for field in legacy["fields"]:
            if field["name"] == "KP2BW_SYNC":
                field["value"] = stamp
        bw.update_item(legacy["id"], legacy)
    migrate()
    initial = read()
    for title in ("Credit Card", "Identity", "Secure Note"):
        assert any(
            f["name"] == "KeePass:KP2BW_HISTORY:1" for f in initial[title]["fields"]
        )
        assert not any(f["name"] == "KP2BW_HISTORY" for f in initial[title]["fields"])
    migrate()
    unchanged = read()
    assert {key: value["revisionDate"] for key, value in initial.items()} == {
        key: value["revisionDate"] for key, value in unchanged.items()
    }
    print("native template history upgrade and unchanged rerun passed")


def run_templates_selected_test(vault: Vault) -> None:
    fixture = template_fixture(vault, "templates-selected")
    bw = vault.client
    sources = fixture.sources
    card = sources["Credit Card"]
    db = fixture.db
    fixture.migrate()
    initial = fixture.read()
    check_initial(fixture, initial)
    migrate = fixture.migrate
    read = fixture.read
    card.set_custom_property("CVV", "456", protect=True)
    sources["Identity"].set_custom_property("First Name", "Grace")
    sources["Secure Note"].notes = "Updated secure note"
    db.save()
    vault.kp2bw_parallel([
        (
            vault.migrate_args(
                fixture.source,
                "synthetic",
                extra_args=(
                    "--entry-id",
                    str(sources[title].uuid),
                    "--item-id",
                    initial[title]["id"],
                ),
            ),
            fixture.env,
        )
        for title in ("Credit Card", "Identity", "Secure Note")
    ])
    changed = read()
    assert (
        changed["Credit Card"]["card"]
        and changed["Credit Card"]["card"].get("code") == "456"
    )
    assert (
        changed["Identity"]["identity"]
        and changed["Identity"]["identity"].get("firstName") == "Grace"
    )
    assert changed["Secure Note"]["notes"] == "Updated secure note"
    edited = copy.deepcopy(changed["Credit Card"])
    assert edited["card"] is not None
    edited["card"]["code"] = "789"
    bw.update_item(edited["id"], edited)
    migrate()
    protected = read()["Credit Card"]
    assert protected["card"] and protected["card"].get("code") == "789"
    print("native template selected updates and edit protection passed")


def main() -> None:
    def run_all(vault: Vault) -> None:
        run_templates_cli_test(vault)
        run_templates_test(vault)
        run_templates_selected_test(vault)

    vault_main(run_all)


if __name__ == "__main__":
    main()
