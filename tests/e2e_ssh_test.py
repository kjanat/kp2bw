"""Native SSH creation, rotation, unchanged reruns and edit protection."""

import copy
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from e2e_vaultwarden_test import _run, _run_migration
from pykeepass import create_database

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse


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


def run_ssh_test(tmp: Path, env: dict[str, str], password: str) -> None:
    env = env.copy()
    mapping = tmp / "ssh-map.json"
    mapping.write_text(
        json.dumps([{"group": "SSH", "fields": {"privateKey": "Private Key"}}]),
        encoding="utf-8",
    )
    env.update(KP2BW_SSH_MAP=str(mapping), BW_NOINTERACTION="true")
    source = tmp / "ssh.kdbx"
    db = create_database(source, password="synthetic")
    group = db.add_group(db.root_group, "SSH")
    entry = db.add_entry(group, "Synthetic SSH key", "", "")
    original = private_key()
    entry.set_custom_property("Private Key", original, protect=True)
    broken = db.add_entry(group, "Synthetic unsupported key", "", "")
    broken.set_custom_property("Private Key", "unsupported synthetic key", protect=True)
    db.save()

    def migrate() -> None:
        _run_migration(source, "synthetic", password, env)

    def read() -> tuple[BwItemResponse, BwItemResponse]:
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
            native = bw.get_item_by_uuid(entry.uuid.hex.upper())
            fallback = bw.get_item_by_uuid(broken.uuid.hex.upper())
            assert native is not None and fallback is not None
            return bw.get_item(native["id"]), bw.get_item(fallback["id"])

    migrate()
    initial, fallback = read()
    assert initial["type"] == 5 and initial.get("sshKey")
    assert fallback["type"] == 1
    assert any(f["value"] == original and f["type"] == 1 for f in initial["fields"])
    assert any(
        f["value"] == "unsupported synthetic key" and f["type"] == 1
        for f in fallback["fields"]
    )
    migrate()
    unchanged, unchanged_fallback = read()
    assert unchanged["revisionDate"] == initial["revisionDate"]
    assert unchanged_fallback["revisionDate"] == fallback["revisionDate"]
    entry.set_custom_property("Private Key", private_key(), protect=True)
    db.save()
    migrate()
    rotated, _ = read()
    assert rotated["id"] == initial["id"]
    assert rotated.get("sshKey") != initial.get("sshKey")
    migrate()
    assert read()[0]["revisionDate"] == rotated["revisionDate"]
    with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
        edited = copy.deepcopy(rotated)
        key = edited.get("sshKey")
        assert key is not None
        key["publicKey"] += " manual-comment"
        bw.update_item(edited["id"], edited)
    migrate()
    protected = read()[0]
    assert protected.get("sshKey") == edited.get("sshKey")
    print("native SSH end-to-end test passed")


def main() -> None:
    env = os.environ.copy()
    env["BITWARDENCLI_APPDATA_DIR"] = env["KP2BW_E2E_BW_PROFILE"]
    env["BW_NOINTERACTION"] = "true"
    status = json.loads(_run(["bw", "status"], env=env))
    assert status.get("serverUrl", "").rstrip("/") == env["BW_SERVER_URL"].rstrip("/")
    assert status.get("userEmail", "").casefold() == env["BW_TEST_EMAIL"].casefold()
    with tempfile.TemporaryDirectory() as directory:
        run_ssh_test(Path(directory), env, env["BW_TEST_PASSWORD"])


if __name__ == "__main__":
    main()
