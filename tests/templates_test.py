"""Template classification never guesses from an ordinary entry's title."""

import copy
import tempfile
from pathlib import Path
from typing import cast
from unittest.mock import patch

from convert_update_test import FakeBw, as_bw, make_desired, make_existing
from pykeepass import create_database

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.exceptions import ConversionError
from kp2bw.item_sync import (
    content_signature,
    pre_fido2_content_signature,
    sync_stamp_matches,
)
from kp2bw.source_fields import source_field_name
from kp2bw.templates import (
    TemplateRule,
    apply_template,
    parse_template_overrides,
    plan_template,
    recognize_template,
)


def main() -> None:
    assert (
        recognize_template("49DD48DBFF149445B3392CE90EA75309", "Kreditkarte") == "card"
    )
    assert recognize_template("", "ID Card") == "identity"
    assert recognize_template("", "Gift card account login") is None
    rule = TemplateRule("card", {})
    plan = plan_template(
        rule,
        {
            "Card Number": "4111 1111-1111 1111",
            "Expiry": "03/29",
            "CVV": "123",
            "PIN": "1234",
        },
    )
    assert plan.values == {
        "number": "4111111111111111",
        "expMonth": "3",
        "expYear": "2029",
        "code": "123",
    }
    assert plan.consumed == {"Card Number", "Expiry", "CVV"}
    conflict = plan_template(
        rule,
        {
            "Number": "4111111111111111",
            "Card Number": "5555555555554444",
            "Expiry": "13/29",
        },
    )
    assert not conflict.consumed and not conflict.values and conflict.warnings
    duplicate_name = source_field_name("Number", 2)
    duplicate = plan_template(
        rule, {"Number": "4111111111111111", duplicate_name: "5555555555554444"}
    )
    assert not duplicate.consumed and not duplicate.values and duplicate.warnings
    escaped_identity = source_field_name("KP2BW_ID")
    identity_plan = plan_template(
        TemplateRule("identity", {"KP2BW_ID": "username"}),
        {"KP2BW_ID": "managed-uuid", escaped_identity: "source-username"},
    )
    assert identity_plan.values == {"username": "source-username"}
    assert identity_plan.consumed == {escaped_identity}
    partial = plan_template(rule, {"Expiry": "03/29", "Expiry month": "4"})
    assert "Expiry" not in partial.consumed
    invalid_cases: list[object] = [
        [],
        {"bad": {}},
        {"0" * 32: {"type": "login"}},
        {"0" * 32: {"type": "card", "fields": {"x": "password"}}},
    ]
    for invalid in invalid_cases:
        try:
            parse_template_overrides(invalid)
        except ConversionError:
            pass
        else:
            raise AssertionError("Invalid mapping accepted")
    overrides = parse_template_overrides({
        "0" * 32: {"type": "identity", "fields": {"Naam": "lastName"}}
    })
    assert plan_template(overrides["0" * 32], {"Naam": "Example"}).values == {
        "lastName": "Example"
    }
    conv = Converter(
        "unused", None, None, "unused", None, None, False, 0, None, map_templates=True
    )
    skip = Converter(
        "unused",
        None,
        None,
        "unused",
        None,
        None,
        False,
        0,
        None,
        map_templates=True,
        update_existing=False,
    )
    passkey_login = make_existing(collectionIds=["old"])
    login = passkey_login.get("login")
    assert login is not None
    login["fido2Credentials"] = [
        {
            "credentialId": "synthetic-passkey",
            "keyType": "public-key",
            "keyAlgorithm": "ECDSA",
            "keyCurve": "P-256",
            "keyValue": "synthetic",
            "rpId": "example.test",
            "rpName": "Synthetic",
            "userHandle": "synthetic",
            "userName": "synthetic",
            "userDisplayName": "Synthetic",
            "counter": "0",
            "discoverable": "true",
            "creationDate": None,
        }
    ]
    target = make_desired(
        type=3, card={"number": "4111111111111111"}, collectionIds=["new"]
    )
    client = FakeBw()
    outcome, uploads, stale = skip.reconcile_existing_item(
        as_bw(client),
        passkey_login,
        None,
        target,
        [],
        fixed_coll_id=None,
        kp_uuid="source",
    )
    assert outcome == "collection" and not uploads and not stale
    assert client.updates[0][1].get("login") == login
    assert client.updates[0][1]["type"] == 1
    item = conv.create_bw_python_object(
        "Card",
        "notes",
        "https://example.test",
        "",
        "user",
        "secret",
        {
            "Number": ("4111111111111111", 0),
            "PIN": ("1234", 1),
            "_etm_template_uuid": ("0" * 32, 0),
        },
    )
    identity = copy.deepcopy(item)
    identity["fields"].extend([
        {"name": "KP2BW_ID", "value": "managed-uuid", "type": 0},
        {"name": escaped_identity, "value": "source-username", "type": 0},
    ])
    apply_template(identity, TemplateRule("identity", {"KP2BW_ID": "username"}))
    assert (
        identity["identity"]
        and identity["identity"].get("username") == "source-username"
    )
    assert any(
        field["name"] == "KP2BW_ID" and field["value"] == "managed-uuid"
        for field in identity["fields"]
    )
    assert not any(field["name"] == escaped_identity for field in identity["fields"])
    apply_template(item, rule)
    assert (
        item["type"] == 3
        and item["card"]
        and item["card"].get("number") == "4111111111111111"
    )
    assert any(
        f["name"] == "PIN" and f["value"] == "1234" and f["type"] == 1
        for f in item["fields"]
    )
    assert any(
        f["name"] == "KeePass login data" and f["type"] == 1 and "secret" in f["value"]
        for f in item["fields"]
    )
    existing = cast(BwItemResponse, copy.deepcopy(item))
    existing.update(id="destination", object="item", revisionDate="revision")
    existing.pop("login", None)
    assert not conv.content_differs(existing, item), (
        "Wire format must retain the same signature"
    )
    assert "login" not in BitwardenServeClient.item_update_body(existing)
    stamp = content_signature(existing)
    assert sync_stamp_matches(existing, stamp)
    assert existing["card"] is not None
    existing["card"]["number"] = "5555555555554444"
    assert conv.is_user_modified(existing)
    assert not sync_stamp_matches(existing, pre_fido2_content_signature(existing)), (
        "Old login-only stamps cannot authenticate native fields"
    )
    assert not sync_stamp_matches(existing, stamp)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "templates.kdbx"
        db = create_database(path, password="synthetic")
        template = db.add_entry(db.root_group, "Credit Card", "", "")
        template.set_custom_property("_etm_template", "1")
        card = db.add_entry(db.root_group, "Account", "user", "secret")
        card.set_custom_property("_etm_template_uuid", template.uuid.hex)
        card.set_custom_property("Number", "4111111111111111")
        alias = db.add_entry(
            db.root_group,
            "Ordinary alias",
            "user",
            f"{{REF:P@I:{card.uuid.hex.upper()}}}",
        )
        alias.url = "https://native-alias.example.test"
        alias.otp = "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP"
        number_node = card._element.find("./String[Key='Number']")
        assert number_node is not None
        duplicate_node = copy.deepcopy(number_node)
        number_value = duplicate_node.find("Value")
        assert number_value is not None
        number_value.text = "5555555555554444"
        card._element.append(duplicate_node)
        ordinary = db.add_entry(db.root_group, "Credit Card", "ordinary", "")
        db.save()
        for enabled in (False, True):
            converter = Converter(
                str(path),
                "synthetic",
                None,
                "unused",
                None,
                None,
                False,
                0,
                None,
                map_templates=enabled,
            )
            with patch.object(
                converter, "create_bitwarden_items_for_entries", return_value=0
            ):
                assert converter.convert() == 0
            items = {
                key: converter.unpack_entry(value)[2]
                for key, value in converter.entries.items()
            }
            assert items[card.uuid.hex.upper()]["type"] == (3 if enabled else 1)
            assert items[ordinary.uuid.hex.upper()]["type"] == 1
            assert (template.uuid.hex.upper() in items) is not enabled
            if enabled:
                mapped_card = items[card.uuid.hex.upper()]
                assert mapped_card["card"] is not None and not mapped_card["card"].get(
                    "number"
                )
                assert {
                    field["value"]
                    for field in mapped_card["fields"]
                    if "Number" in field["name"]
                } == {"4111111111111111", "5555555555554444"}
                alias_item = items[alias.uuid.hex.upper()]
                assert alias_item["type"] == 1
                assert alias_item["login"]["password"] == "secret"
                assert alias_item["login"]["totp"]
                assert any(
                    uri["uri"] == alias.url for uri in alias_item["login"]["uris"]
                )

    print("template mapping tests passed")


if __name__ == "__main__":
    main()
