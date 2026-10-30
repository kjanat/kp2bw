"""Explicit source selectors, lossless fallback and native SSH edit protection."""

import copy
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, call, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pykeepass import create_database

from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.exceptions import BitwardenClientError, ConversionError
from kp2bw.item_sync import content_signature
from kp2bw.ssh_mapping import apply_ssh_rule, parse_ssh_rules


def check_excluded_ssh_rules() -> None:
    rules = parse_ssh_rules([
        {"field": {"name": "Type", "value": "SSH"}, "fields": {"privateKey": "Key"}},
        {
            "field": {"name": "Title", "value": "Excluded"},
            "fields": {"privateKey": "Key"},
        },
    ])
    with tempfile.TemporaryDirectory() as directory:
        for exclusion in ("expired", "recycled", "tag"):
            path = Path(directory) / f"{exclusion}.kdbx"
            db = create_database(path, password="synthetic")
            active = db.add_entry(db.root_group, "Active", "user", "pw")
            active.tags = ["included"]
            excluded = db.add_entry(db.root_group, "Excluded", "user", "pw")
            excluded.set_custom_property("Type", "SSH")
            if exclusion == "expired":
                excluded.expires = True
                excluded.expiry_time = datetime(2000, 1, 1, tzinfo=UTC)
            elif exclusion == "recycled":
                db.trash_entry(excluded)
            db.save()
            converter = Converter(
                str(path),
                "synthetic",
                None,
                "unused",
                None,
                None,
                False,
                0,
                ["included"] if exclusion == "tag" else None,
                ssh_rules=rules,
                skip_expired=exclusion == "expired",
            )
            converter.load_keepass_data()
            assert set(converter.entries) == {active.uuid.hex.upper()}
            converter.skip_expired = False
            converter.include_recyclebin = True
            converter.import_tags = None
            try:
                converter.load_keepass_data()
            except ConversionError:
                pass
            else:
                raise AssertionError("Included ambiguous SSH mapping was accepted")


def main() -> None:
    check_excluded_ssh_rules()
    private = (
        ed25519.Ed25519PrivateKey
        .generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        .decode()
    )
    rules = parse_ssh_rules([
        {"group": "Work/Servers", "fields": {"privateKey": "Private Key"}},
        {"group": "Referenced keys", "fields": {"privateKey": "Password"}},
    ])
    assert rules[0].matches("Work/Servers", None, {})
    assert not rules[0].matches("Servers", None, {})
    discriminator = parse_ssh_rules([
        {
            "field": {"name": "Type", "value": "SSH"},
            "fields": {"privateKey": "Private Key"},
        }
    ])[0]
    assert discriminator.matches("", None, {"Type": "SSH"})
    assert not discriminator.matches("", None, {"Title": "SSH"})
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "ssh.kdbx"
        db = create_database(path, password="synthetic")
        group = db.add_group(db.add_group(db.root_group, "Work"), "Servers")
        entry = db.add_entry(group, "Account", "user", "password")
        entry.set_custom_property("Private Key", private, protect=True)
        ordinary = db.add_entry(db.root_group, "SSH Key", "", "")
        ordinary.set_custom_property("Private Key", private, protect=True)
        alias = db.add_entry(
            db.root_group,
            "SSH login alias",
            "{REF:U@I:" + entry.uuid.hex.upper() + "}",
            "{REF:P@I:" + entry.uuid.hex.upper() + "}",
            url="https://ssh-login.example.test",
        )
        key_source = db.add_entry(db.root_group, "Key source", "user", private)
        selected_alias = db.add_entry(
            db.add_group(db.root_group, "Referenced keys"),
            "Selected SSH alias",
            "user",
            "{REF:P@I:" + key_source.uuid.hex.upper() + "}",
        )
        chained_alias = db.add_entry(
            db.root_group,
            "Chained login alias",
            "{REF:U@I:" + selected_alias.uuid.hex.upper() + "}",
            "{REF:P@I:" + selected_alias.uuid.hex.upper() + "}",
            url="https://chained-login.example.test",
        )
        db.save()
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
            ssh_rules=rules,
        )
        with patch.object(
            converter, "create_bitwarden_items_for_entries", return_value=0
        ):
            assert converter.convert() == 0
        item = converter.unpack_entry(converter.entries[entry.uuid.hex.upper()])[2]
        assert item["type"] == 5 and item.get("sshKey")
        selected_item = converter.unpack_entry(
            converter.entries[selected_alias.uuid.hex.upper()]
        )[2]
        assert selected_item["type"] == 5 and selected_item.get("sshKey")
        chained_item = converter._unpack_entry(
            converter._entries[chained_alias.uuid.hex.upper()]
        )[2]
        assert chained_item["type"] == 1
        assert chained_item["login"]["username"] == "user"
        assert chained_item["login"]["password"] == private
        assert chained_item["login"]["uris"] == [
            {"uri": "https://chained-login.example.test", "match": None}
        ]
        assert (
            converter.unpack_entry(converter.entries[key_source.uuid.hex.upper()])[2][
                "type"
            ]
            == 1
        )

        alias_item = converter.unpack_entry(converter.entries[alias.uuid.hex.upper()])[
            2
        ]
        assert alias_item["type"] == 1
        assert alias_item["login"]["username"] == "user"
        assert alias_item["login"]["password"] == "password"
        assert alias_item["login"]["uris"] == [
            {"uri": "https://ssh-login.example.test", "match": None}
        ]

        assert (
            converter.unpack_entry(converter.entries[ordinary.uuid.hex.upper()])[2][
                "type"
            ]
            == 1
        )
        assert any(
            field["value"] == private and field["type"] == 1 for field in item["fields"]
        )
        existing = cast(BwItemResponse, copy.deepcopy(item))
        existing.update(id="destination", object="item", revisionDate="revision")
        existing.pop("login", None)
        assert content_signature(existing) == content_signature(item)
        ssh = existing.get("sshKey")
        assert ssh is not None
        ssh["publicKey"] += " changed"
        assert converter.is_user_modified(existing)
        skip_only = Converter(
            "unused",
            "unused",
            None,
            "unused",
            None,
            None,
            False,
            0,
            None,
            update_existing=False,
        )
        skipped_client = MagicMock()
        fallback_item = converter.create_bw_python_object(
            "Account", "user", "password", "", "", "", {}
        )
        fallback_item["collectionIds"] = ["new-collection"]
        outcome, uploads, stale = skip_only.reconcile_existing_item(
            skipped_client,
            existing,
            None,
            fallback_item,
            [],
            fixed_coll_id=None,
            kp_uuid=entry.uuid.hex.upper(),
        )
        assert outcome == "collection" and not uploads and not stale
        assert skipped_client.update_item.call_args.args[1]["type"] == 5
        assert skipped_client.update_item.call_args.args[1]["sshKey"] == existing.get(
            "sshKey"
        )
        client = MagicMock()
        client.require_ssh_supported.side_effect = BitwardenClientError(
            "Organization policy forbids SSH items"
        )
        with patch("kp2bw.convert.BitwardenServeClient") as factory:
            factory.return_value.__enter__.return_value = client
            try:
                converter.create_bitwarden_items_for_entries()
            except BitwardenClientError:
                pass
            else:
                raise AssertionError("Rejected SSH policy must stop the migration")
        assert client.mock_calls == [call.require_ssh_supported()], (
            "Policy rejection must precede all folder, collection and item operations"
        )
        fallback = converter.create_bw_python_object("Broken", "", "", "", "", "", {})
        source = "unsupported private format " * 1000
        files, warnings = apply_ssh_rule(fallback, {"Private Key": source}, rules[0])
        assert fallback["type"] == 1 and warnings and len(files) == 1
        assert files[0].data == source.encode(), (
            "Unsupported large keys must survive verbatim"
        )
    print("SSH mapping tests passed")


if __name__ == "__main__":
    main()
