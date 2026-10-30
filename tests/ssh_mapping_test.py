"""Explicit source selectors, lossless fallback and native SSH edit protection."""

import copy
import tempfile
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, call, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pykeepass import create_database

from kp2bw._item_sync import content_signature
from kp2bw._ssh_mapping import apply_ssh_rule, parse_ssh_rules
from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.exceptions import BitwardenClientError


def main() -> None:
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
        {"group": "Work/Servers", "fields": {"privateKey": "Private Key"}}
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
            converter, "_create_bitwarden_items_for_entries", return_value=0
        ):
            assert converter.convert() == 0
        item = converter._unpack_entry(converter._entries[entry.uuid.hex.upper()])[2]
        assert item["type"] == 5 and item.get("sshKey")
        alias_item = converter._unpack_entry(
            converter._entries[alias.uuid.hex.upper()]
        )[2]
        assert alias_item["type"] == 1
        assert alias_item["login"]["username"] == "user"
        assert alias_item["login"]["password"] == "password"
        assert alias_item["login"]["uris"] == [
            {"uri": "https://ssh-login.example.test", "match": None}
        ]

        assert (
            converter._unpack_entry(converter._entries[ordinary.uuid.hex.upper()])[2][
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
        assert converter._is_user_modified(existing)
        client = MagicMock()
        client.require_ssh_supported.side_effect = BitwardenClientError(
            "Organization policy forbids SSH items"
        )
        with patch("kp2bw.convert.BitwardenServeClient") as factory:
            factory.return_value.__enter__.return_value = client
            try:
                converter._create_bitwarden_items_for_entries()
            except BitwardenClientError:
                pass
            else:
                raise AssertionError("Rejected SSH policy must stop the migration")
        assert client.mock_calls == [call.require_ssh_supported()], (
            "Policy rejection must precede all folder, collection and item operations"
        )
        fallback = converter._create_bw_python_object("Broken", "", "", "", "", "", {})
        source = "unsupported private format " * 1000
        files, warnings = apply_ssh_rule(fallback, {"Private Key": source}, rules[0])
        assert fallback["type"] == 1 and warnings and len(files) == 1
        assert files[0].data == source.encode(), (
            "Unsupported large keys must survive verbatim"
        )
    print("SSH mapping tests passed")


if __name__ == "__main__":
    main()
