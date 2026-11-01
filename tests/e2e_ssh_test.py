"""Native SSH creation, rotation, unchanged reruns and edit protection."""

import copy
import json
from datetime import UTC, datetime
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from e2e_support import Vault, vault_main
from pykeepass import create_database

from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.ssh_mapping import parse_ssh_rules


def private_key() -> str:
    return (
        ed25519.Ed25519PrivateKey
        .generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        .decode()
    )


def ssh_scenario(
    vault: Vault, name: str, mode: Literal["cli", "rerun", "rotation", "protected"]
) -> None:
    tmp = vault.tmp / name
    tmp.mkdir()
    rules = [
        {"group": "SSH", "fields": {"privateKey": "Private Key"}},
        {"group": "Referenced keys", "fields": {"privateKey": "Password"}},
        {
            "field": {"name": "Type", "value": "Excluded"},
            "fields": {"privateKey": "Private Key"},
        },
    ]
    mapping = tmp / "ssh-map.json"
    mapping.write_text(json.dumps(rules), encoding="utf-8")
    env = {"KP2BW_SSH_MAP": str(mapping), "KP2BW_SKIP_EXPIRED": "true"}
    source = tmp / "ssh.kdbx"
    db = create_database(source, password="synthetic")
    group = db.add_group(db.root_group, "SSH")
    excluded = db.add_entry(group, "Excluded ambiguous SSH key", "", "")
    excluded.set_custom_property("Type", "Excluded")
    excluded.expires = True
    excluded.expiry_time = datetime(2000, 1, 1, tzinfo=UTC)
    entry = db.add_entry(group, "Synthetic SSH key", "ssh-user", "synthetic-password")
    alias = db.add_entry(
        db.root_group,
        "Synthetic SSH login alias",
        "{REF:U@I:" + entry.uuid.hex.upper() + "}",
        "{REF:P@I:" + entry.uuid.hex.upper() + "}",
        url="https://ssh-login.example.test",
    )
    original = private_key()
    key_source = db.add_entry(
        db.root_group, "Referenced key source", "chain-user", original
    )
    chain_target = db.add_entry(
        db.add_group(db.root_group, "Referenced keys"),
        "Referenced SSH target",
        "{REF:U@I:" + key_source.uuid.hex.upper() + "}",
        "{REF:P@I:" + key_source.uuid.hex.upper() + "}",
    )
    chain_alias = db.add_entry(
        db.root_group,
        "Chained SSH login alias",
        "{REF:U@I:" + chain_target.uuid.hex.upper() + "}",
        "{REF:P@I:" + chain_target.uuid.hex.upper() + "}",
        url="https://chained-login.example.test",
    )
    entry.set_custom_property("Private Key", original, protect=True)
    broken = db.add_entry(group, "Synthetic unsupported key", "", "")
    broken.set_custom_property("Private Key", "unsupported synthetic key", protect=True)
    db.save()

    def migrate() -> None:
        converter = Converter(
            str(source),
            "synthetic",
            None,
            vault.password,
            None,
            None,
            False,
            999,
            None,
            skip_expired=True,
            migrate_metadata=False,
            ssh_rules=parse_ssh_rules(rules),
        )
        assert converter.convert(vault.client) == 0

    alias_revision: str | None = None
    chain_revisions: tuple[str | None, str | None] | None = None

    def read() -> tuple[BwItemResponse, BwItemResponse]:
        nonlocal alias_revision, chain_revisions
        target = vault.item(chain_target.uuid.hex.upper())
        chained = vault.item(chain_alias.uuid.hex.upper())
        assert target["type"] == 5 and target.get("sshKey")
        chain_login = chained.get("login")
        assert chained["type"] == 1 and chain_login is not None
        assert chain_login["username"] == "chain-user"
        assert chain_login["password"] == original
        assert any(
            uri["uri"] == "https://chained-login.example.test"
            for uri in chain_login["uris"]
        )
        revisions = (target.get("revisionDate"), chained.get("revisionDate"))
        if chain_revisions is not None:
            assert revisions == chain_revisions
        chain_revisions = revisions
        assert vault.find(excluded.uuid.hex.upper()) is None
        login = vault.item(alias.uuid.hex.upper())
        credentials = login.get("login")
        assert credentials is not None
        assert login["type"] == 1 and credentials["username"] == "ssh-user"
        assert credentials["password"] == "synthetic-password"
        assert any(
            uri["uri"] == "https://ssh-login.example.test"
            for uri in credentials["uris"]
        )
        if alias_revision is not None:
            assert login["revisionDate"] == alias_revision
        alias_revision = login["revisionDate"]
        return vault.item(entry.uuid.hex.upper()), vault.item(broken.uuid.hex.upper())

    if mode == "cli":
        vault.migrate(source, "synthetic", env=env)
    else:
        migrate()
    initial, fallback = read()
    assert initial["type"] == 5 and initial.get("sshKey")
    assert fallback["type"] == 1
    assert any(f["value"] == original and f["type"] == 1 for f in initial["fields"])
    assert any(
        f["value"] == "unsupported synthetic key" and f["type"] == 1
        for f in fallback["fields"]
    )
    if mode == "cli":
        print("native SSH CLI import passed")
        return
    if mode == "rerun":
        migrate()
        unchanged, unchanged_fallback = read()
        assert unchanged["revisionDate"] == initial["revisionDate"]
        assert unchanged_fallback["revisionDate"] == fallback["revisionDate"]
        print("native SSH unchanged rerun passed")
        return
    if mode == "rotation":
        entry.set_custom_property("Private Key", private_key(), protect=True)
        db.save()
        vault.migrate(
            source,
            "synthetic",
            extra_args=("--entry-id", str(entry.uuid), "--item-id", initial["id"]),
            env=env,
        )
        rotated, _ = read()
        assert rotated["id"] == initial["id"]
        assert rotated.get("sshKey") != initial.get("sshKey")
        migrate()
        assert read()[0]["revisionDate"] == rotated["revisionDate"]
        print("native SSH key rotation passed")
        return
    edited = copy.deepcopy(initial)
    key = edited.get("sshKey")
    assert key is not None
    key["publicKey"] += " manual-comment"
    vault.client.update_item(edited["id"], edited)
    migrate()
    protected = read()[0]
    assert protected.get("sshKey") == edited.get("sshKey")
    print("native SSH manual edit protection passed")


def run_ssh_cli_test(vault: Vault) -> None:
    ssh_scenario(vault, "ssh-cli", "cli")


def run_ssh_test(vault: Vault) -> None:
    ssh_scenario(vault, "ssh", "rerun")


def run_ssh_rotation_test(vault: Vault) -> None:
    ssh_scenario(vault, "ssh-rotation", "rotation")


def run_ssh_protected_test(vault: Vault) -> None:
    ssh_scenario(vault, "ssh-protected", "protected")


def main() -> None:
    def run_all(vault: Vault) -> None:
        run_ssh_cli_test(vault)
        run_ssh_test(vault)
        run_ssh_rotation_test(vault)
        run_ssh_protected_test(vault)

    vault_main(run_all)


if __name__ == "__main__":
    main()
