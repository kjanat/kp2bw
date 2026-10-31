"""Live multi-file regression using the disposable integration account.

One fault-injected conversion acknowledges a replacement without storing it,
to verify the old file survives.
"""

import logging
import os
import uuid
from unittest.mock import patch

import httpx
from e2e_support import Vault, vault_main
from pykeepass import create_database

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.convert import Converter

logger = logging.getLogger("e2e.attachments")


def run_attachment_batch_test(vault: Vault) -> None:
    kp_password = "SyntheticAttachmentPassword123!"
    run_id = uuid.uuid4().hex
    source = vault.tmp / "attachments.kdbx"
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

    def converter() -> Converter:
        return Converter(
            str(source),
            kp_password,
            None,
            vault.password,
            None,
            None,
            False,
            999,
            None,
            migrate_metadata=False,
        )

    def migrate() -> None:
        assert converter().convert(vault.client) == 0

    def verify() -> dict[str, tuple[str, tuple[str, ...]]]:
        items = vault.named(*expected)
        state: dict[str, tuple[str, tuple[str, ...]]] = {}
        for name, files in expected.items():
            item = items[name]
            attachments = item.get("attachments") or []
            assert len(attachments) == len(files)
            assert {att["fileName"] for att in attachments} == set(files)
            for filename, contents in files.items():
                assert vault.attachment(item["id"], filename) == contents.encode()
            state[name] = (
                item["revisionDate"],
                tuple(sorted(att["id"] for att in attachments)),
            )
        return state

    try:
        logger.info("Testing eight files across two items")
        migrate()
        initial = verify()
        migrate()
        assert verify() == initial, "Unchanged import rewrote or duplicated attachments"

        entry = db.entries[0]
        first = entry.attachments[0]
        assert first.filename is not None
        first.id = db.add_binary(b"verified replacement")
        expected[entry.title or ""][first.filename] = "verified replacement"
        db.save()
        logger.info("Testing verified attachment replacement")
        migrate()
        replaced = verify()
        migrate()
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
        with patch.object(BitwardenServeClient, "upload_attachment", false_success):
            failures = converter().convert(vault.client)
        assert acknowledged == [first.filename]
        assert failures == 1, "An unverified upload must fail the conversion"
        assert verify() == replaced, (
            "Failed replacement deleted or changed the old attachment"
        )
    finally:
        if os.environ.get("KP2BW_E2E_CLEANUP") == "1":
            # Only delete this run's synthetic items, matching both the
            # random name and the source UUID; never purge the test vault.
            vault.delete_sources(
                {entry.uuid.hex.upper() for entry in db.entries}, expected.keys()
            )
    print("live attachment serialization and verification regression passed")


def main() -> None:
    vault_main(run_attachment_batch_test)


if __name__ == "__main__":
    main()
