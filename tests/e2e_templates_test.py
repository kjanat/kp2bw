"""Native templates survive real CLI creation, updates and unchanged reruns."""

import copy
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from e2e_vaultwarden_test import login_session, run, run_migration
from pykeepass import Entry, create_database

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse
from kp2bw.item_sync import pre_history_content_signature


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    server = os.environ.get("BW_SERVER_URL", "https://localhost:18443")
    cert = os.environ.get(
        "BW_CERT_PATH", str(root / "tests/fixtures/vaultwarden-certs/cert.pem")
    )
    password = os.environ.get("BW_TEST_PASSWORD", "TestMasterPassword123!")
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        env = os.environ.copy()
        env.update(
            BITWARDENCLI_APPDATA_DIR=str(tmp / "bw"),
            NODE_EXTRA_CA_CERTS=cert,
            BW_NOINTERACTION="true",
            KP2BW_MAP_TEMPLATES="true",
        )
        run(["bw", "config", "server", server], env=env)
        login_session(
            env, os.environ.get("BW_TEST_EMAIL", "integration@example.com"), password
        )
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
        env["KP2BW_TEMPLATE_MAP"] = str(mapping)
        db.save()

        def migrate() -> None:
            run_migration(source, "synthetic", password, env)

        def read() -> dict[str, BwItemResponse]:
            with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
                result: dict[str, BwItemResponse] = {}
                for title, entry in sources.items():
                    listed = bw.get_item_by_uuid(entry.uuid.hex.upper())
                    assert listed is not None
                    result[title] = bw.get_item(listed["id"])
                return result

        migrate()
        initial = read()
        assert [initial[key]["type"] for key in sources] == [3, 4, 2, 1, 3]
        conflict_card = initial["Conflicting Card"]["card"]
        assert conflict_card is not None and not conflict_card.get("number")
        assert {
            field["value"]
            for field in initial["Conflicting Card"]["fields"]
            if "Number" in field["name"]
        } == {"4111111111111111", "5555555555554444"}
        native_card = initial["Credit Card"]["card"]
        assert (
            native_card is not None and native_card.get("number") == "4111111111111111"
        )
        assert (
            native_card.get("expMonth") == "3" and native_card.get("expYear") == "2029"
        )
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
        # Reproduce pre-history native imports with an ordinary marker-name field.
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
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
            assert not any(
                f["name"] == "KP2BW_HISTORY" for f in initial[title]["fields"]
            )
        migrate()
        unchanged = read()
        assert {key: value["revisionDate"] for key, value in initial.items()} == {
            key: value["revisionDate"] for key, value in unchanged.items()
        }
        card.set_custom_property("CVV", "456", protect=True)
        sources["Identity"].set_custom_property("First Name", "Grace")
        sources["Secure Note"].notes = "Updated secure note"
        db.save()
        for title in ("Credit Card", "Identity", "Secure Note"):
            run_migration(
                source,
                "synthetic",
                password,
                env,
                extra_args=(
                    "--entry-id",
                    str(sources[title].uuid),
                    "--item-id",
                    initial[title]["id"],
                ),
            )
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
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
            edited = copy.deepcopy(changed["Credit Card"])
            assert edited["card"] is not None
            edited["card"]["code"] = "789"
            bw.update_item(edited["id"], edited)
        migrate()
        protected = read()["Credit Card"]
        assert protected["card"] and protected["card"].get("code") == "789"
        print("native template end-to-end test passed")


if __name__ == "__main__":
    main()
