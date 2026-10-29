"""Live multi-file regression using the disposable integration account.

All normal passes invoke the installed CLI. One fault-injected conversion
acknowledges a replacement without storing it, to verify the old file survives.
"""

import json
import logging
import os
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import httpx
from _snapshot import as_object
from e2e_vaultwarden_test import (
    _bw_json,
    _get_attachment_text,
    _get_session,
    _login_session,
    _run,
    _run_migration,
)
from pykeepass import create_database

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.convert import Converter

logger = logging.getLogger("e2e.attachments")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    server = os.environ.get("BW_SERVER_URL", "https://localhost:18443")
    cert = os.environ.get(
        "BW_CERT_PATH", str(root / "tests/fixtures/vaultwarden-certs/cert.pem")
    )
    email = os.environ.get("BW_TEST_EMAIL", "integration@example.com")
    password = os.environ.get("BW_TEST_PASSWORD", "TestMasterPassword123!")
    kp_password = "SyntheticAttachmentPassword123!"
    run_id = uuid.uuid4().hex
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        env = os.environ.copy()
        profile = os.environ.get("KP2BW_E2E_BW_PROFILE")
        env.update(
            BITWARDENCLI_APPDATA_DIR=profile or str(tmp / "bw"),
            NODE_EXTRA_CA_CERTS=cert,
        )
        env["BW_NOINTERACTION"] = "true"
        if profile:
            # Reuse an authenticated test account without registering another
            # device or triggering Cloud email verification on every run.
            status = json.loads(_run(["bw", "status"], env=env))
            assert status.get("serverUrl", "").rstrip("/") == server.rstrip("/"), (
                "Saved CLI profile targets a different server"
            )
            assert status.get("userEmail", "").casefold() == email.casefold(), (
                "Saved CLI profile belongs to a different test account"
            )
            _get_session(env, password)
        else:
            _run(["bw", "config", "server", server], env=env)
            _login_session(env, email, password)
        source = tmp / "attachments.kdbx"
        db = create_database(source, password=kp_password)
        expected: dict[str, dict[str, str]] = {}
        for index in range(2):
            name = f"Attachment batch {run_id} {index}"
            entry = db.add_entry(
                db.root_group, name, "synthetic-user", "synthetic-password"
            )
            expected[name] = {}
            for number in range(4):
                filename = f"file-{number}.txt"
                contents = f"distinct item {index}, attachment {number}"
                expected[name][filename] = contents
                entry.add_attachment(db.add_binary(contents.encode()), filename)
        db.save()

        def verify() -> dict[str, tuple[str, tuple[str, ...]]]:
            session = _get_session(env, password)
            _run(["bw", "sync", "--session", session], env=env)
            items = _bw_json(env, "list", "items", "--session", session)
            state: dict[str, tuple[str, tuple[str, ...]]] = {}
            for name, files in expected.items():
                matches = [item for item in items if item.get("name") == name]
                assert len(matches) == 1, "Missing or duplicated attachment test item"
                item = matches[0]
                attachments = item.get("attachments")
                assert isinstance(attachments, list) and len(attachments) == len(files)
                assert {
                    str(as_object(att).get("fileName")) for att in attachments
                } == set(files)
                for filename, contents in files.items():
                    assert (
                        _get_attachment_text(env, session, str(item["id"]), filename)
                        == contents
                    )
                state[name] = (
                    str(item["revisionDate"]),
                    tuple(sorted(str(as_object(att)["id"]) for att in attachments)),
                )
            return state

        try:
            logger.info("Testing eight files across two items")
            _run_migration(source, kp_password, password, env)
            initial = verify()
            _run_migration(source, kp_password, password, env)
            assert verify() == initial, (
                "Unchanged import rewrote or duplicated attachments"
            )

            entry = db.entries[0]
            first = entry.attachments[0]
            assert first.filename is not None
            first.id = db.add_binary(b"verified replacement")
            expected[entry.title or ""][first.filename] = "verified replacement"
            db.save()
            logger.info("Testing verified attachment replacement")
            _run_migration(source, kp_password, password, env)
            replaced = verify()
            _run_migration(source, kp_password, password, env)
            assert verify() == replaced, "Replacement rerun changed attachments"

            first.id = db.add_binary(b"acknowledged but never stored")
            db.save()
            acknowledged: list[str] = []

            async def false_success(
                self: BitwardenServeClient,
                client: httpx.AsyncClient,
                item_id: str,
                filename: str,
                data: bytes,
            ) -> None:
                acknowledged.append(filename)
                # Simulate the server/CLI returning success without keeping bytes.

            logger.info("Testing that an unverified replacement retains the old file")
            with (
                patch.dict(os.environ, env),
                patch.object(BitwardenServeClient, "upload_attachment", false_success),
            ):
                converter = Converter(
                    str(source),
                    kp_password,
                    None,
                    password,
                    None,
                    None,
                    False,
                    999,
                    None,
                    migrate_metadata=False,
                )
                failures = converter.convert()
            assert acknowledged == [first.filename]
            assert failures == 1, "An unverified upload must fail the conversion"
            assert verify() == replaced, (
                "Failed replacement deleted or changed the old attachment"
            )
        finally:
            if os.environ.get("KP2BW_E2E_CLEANUP") == "1":
                # Only delete this run's synthetic items, matching both the
                # random name and the source UUID; never purge the test vault.
                source_ids = {entry.uuid.hex.upper() for entry in db.entries}
                session = _get_session(env, password)
                _run(["bw", "sync", "--session", session], env=env)
                for item in _bw_json(env, "list", "items", "--session", session):
                    if str(item.get("name")) not in expected:
                        continue
                    fields = item.get("fields")
                    if not isinstance(fields, list):
                        continue
                    if any(
                        as_object(field).get("name") == "KP2BW_ID"
                        and str(as_object(field).get("value")) in source_ids
                        for field in fields
                    ):
                        _run(
                            [
                                "bw",
                                "delete",
                                "item",
                                str(item["id"]),
                                "--permanent",
                                "--session",
                                session,
                            ],
                            env=env,
                        )
    print("live attachment serialization and verification regression passed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
