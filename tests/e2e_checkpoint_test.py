"""Verified reruns avoid attachment bodies; remote changes invalidate the cache."""

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Never
from unittest.mock import patch

from e2e_support import Vault, vault_main
from pykeepass import create_database

from kp2bw.attachments import AttachmentPlan
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.checkpoint import CheckpointRecord
from kp2bw.convert import Converter


def converter_for(source: Path, checkpoint: Path, password: str) -> Converter:
    return Converter(
        str(source),
        "synthetic",
        None,
        password,
        None,
        None,
        False,
        999,
        None,
        migrate_metadata=False,
        checkpoint_path=str(checkpoint),
    )


def crash_migration(mode: str, source: Path, checkpoint: Path) -> None:
    original_upload = BitwardenServeClient.upload_attachments
    original_persist = Converter.persist_attachment_plan
    original_delete = BitwardenServeClient.delete_attachment
    original_start = BitwardenServeClient.start_serve
    servers: list[subprocess.Popen[bytes]] = []

    def start(client: BitwardenServeClient, session: str | None) -> None:
        original_start(client, session)
        assert client.serve_process is not None
        servers.append(client.serve_process)

    def crash() -> Never:
        for server in servers:
            try:
                os.killpg(server.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _ = server.wait(timeout=10)
        os._exit(91)

    def upload(
        client: BitwardenServeClient,
        items: list[tuple[str, list[tuple[str, bytes]]]],
        *,
        max_concurrency: int = 4,
    ) -> list[tuple[str, str]]:
        if mode == "before-upload":
            crash()
        result = original_upload(client, items, max_concurrency=max_concurrency)
        if mode == "after-upload" and not result:
            crash()
        return result

    def persist(
        converter: Converter,
        bw: BitwardenServeClient,
        item_id: str,
        plan: AttachmentPlan,
        failed: set[tuple[str, str]],
    ) -> None:
        original_persist(converter, bw, item_id, plan, failed)
        if mode == "after-mapping":
            crash()

    def delete(client: BitwardenServeClient, item_id: str, attachment_id: str) -> None:
        original_delete(client, item_id, attachment_id)
        if mode == "after-delete":
            crash()

    with (
        patch.object(BitwardenServeClient, "start_serve", start),
        patch.object(BitwardenServeClient, "upload_attachments", upload),
        patch.object(Converter, "persist_attachment_plan", persist),
        patch.object(BitwardenServeClient, "delete_attachment", delete),
    ):
        result = converter_for(
            source, checkpoint, os.environ["BW_TEST_PASSWORD"]
        ).convert()
        raise AssertionError(
            f"Crash boundary was not reached (migration result {result})"
        )


def run_crash(mode: str, source: Path, checkpoint: Path, vault: Vault) -> None:
    if os.name != "posix":
        raise AssertionError(
            "Hard-kill integration regression requires POSIX process groups"
        )
    process = vault.child(Path(__file__).resolve(), mode, str(source), str(checkpoint))
    try:
        assert process.wait(timeout=180) == 91, (
            "Migration did not reach its crash boundary"
        )
    finally:
        # The child exits without cleanup deliberately. Terminate only this
        # fixture's process group, including its bw serve child, before restart.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _ = process.wait(timeout=10)
    vault.sync()


def remove_uploaded_body(checkpoint: Path, vault: Vault, container: str) -> None:
    """Leave a real orphan slot only inside the explicitly selected test container."""
    assert vault.account.server.startswith("https://localhost:")
    assert vault.account.email == "integration@example.com"
    records = [
        CheckpointRecord.parse(value)
        for value in json.loads(checkpoint.read_text())["records"]
    ]
    assert len(records) == 1 and records[0].phase == "pending"
    pending = records[0]
    item = vault.client.get_item(pending.item_id)
    matches = [
        att["id"]
        for att in item.get("attachments") or []
        if att["id"] not in pending.before_ids
        and hashlib.sha256(att["fileName"].encode()).hexdigest() == pending.name_digest
    ]
    assert len(matches) == 1
    assert re.fullmatch(r"[a-zA-Z0-9_-]+", pending.item_id) and re.fullmatch(
        r"[a-zA-Z0-9_-]+", matches[0]
    )
    result = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "rm",
            "--",
            f"/data/attachments/{pending.item_id}/{matches[0]}",
        ],
        check=False,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, "Could not remove the synthetic uploaded body"


class CheckpointFixture:
    def __init__(self, vault: Vault, name: str) -> None:
        self.vault = vault
        self.source = vault.tmp / f"{name}.kdbx"
        self.checkpoint = vault.tmp / f"{name}-checkpoint.json"
        self.db = create_database(self.source, password="synthetic")
        self.entry = self.db.add_entry(
            self.db.root_group, f"Synthetic checkpoint {name}", "", ""
        )
        self.entry.add_attachment(
            self.db.add_binary(b"synthetic checkpoint contents"), "file.txt"
        )
        self.db.save()
        self.downloads = 0
        self.uploads = 0

    def replace(self, contents: bytes) -> None:
        self.entry.attachments[0].id = self.db.add_binary(contents)
        self.db.save()

    def migrate(self) -> None:
        original_download = BitwardenServeClient.get_attachment
        original_upload = BitwardenServeClient.upload_attachments

        def download(
            client: BitwardenServeClient, item_id: str, attachment_id: str
        ) -> bytes:
            self.downloads += 1
            return original_download(client, item_id, attachment_id)

        def upload(
            client: BitwardenServeClient,
            items: list[tuple[str, list[tuple[str, bytes]]]],
            *,
            max_concurrency: int = 4,
        ) -> list[tuple[str, str]]:
            self.uploads += sum(len(files) for _, files in items)
            return original_upload(client, items, max_concurrency=max_concurrency)

        self.uploads = self.downloads = 0
        with (
            patch.object(BitwardenServeClient, "get_attachment", download),
            patch.object(BitwardenServeClient, "upload_attachments", upload),
        ):
            converter = converter_for(self.source, self.checkpoint, self.vault.password)
            assert converter.convert(self.vault.client) == 0


def run_checkpoint_test(vault: Vault) -> None:
    fixture = CheckpointFixture(vault, "checkpoint")
    fixture.migrate()
    assert fixture.uploads == 1 and fixture.downloads > 0
    fixture.migrate()
    assert fixture.uploads == fixture.downloads == 0, (
        "An unchanged verified rerun must not transfer attachment bodies"
    )
    item = vault.item(fixture.entry.uuid.hex.upper())
    item["favorite"] = True
    vault.client.update_item(item["id"], item)
    fixture.migrate()
    assert fixture.downloads > 0 and fixture.uploads == 0, (
        "A changed remote revision must invalidate cached verification"
    )
    fixture.migrate()
    assert fixture.uploads == fixture.downloads == 0
    fixture.checkpoint.write_text("{", encoding="utf-8")
    fixture.migrate()
    assert fixture.downloads > 0 and fixture.uploads == 0, (
        "A corrupt checkpoint must safely reverify without reupload"
    )
    print("live attachment checkpoint cache test passed")


def run_crash_recovery(vault: Vault, mode: str) -> None:
    container = vault.account.container
    if mode == "orphan-slot" and not container:
        print("orphan-slot recovery needs KP2BW_E2E_VAULTWARDEN_CONTAINER; skipped")
        return
    fixture = CheckpointFixture(vault, f"crash-{mode}")
    fixture.migrate()
    assert fixture.uploads == 1
    contents = ("replacement at " + mode).encode()
    fixture.replace(contents)
    run_crash(
        "after-upload" if mode in {"orphan-slot", "lost-checkpoint"} else mode,
        fixture.source,
        fixture.checkpoint,
        vault,
    )
    if mode == "orphan-slot" and container:
        remove_uploaded_body(fixture.checkpoint, vault, container)
    elif mode == "lost-checkpoint":
        fixture.checkpoint.unlink()
    fixture.migrate()
    assert fixture.uploads == (1 if mode in {"before-upload", "orphan-slot"} else 0), (
        "Recovery repeated a completed byte upload"
    )
    recovered = vault.item(fixture.entry.uuid.hex.upper())
    attachments = recovered.get("attachments") or []
    assert len(attachments) == 1, (
        "Replacement recovery must converge to one mapped file"
    )
    assert vault.attachment(recovered["id"], attachments[0]["fileName"]) == contents
    fixture.migrate()
    assert fixture.uploads == fixture.downloads == 0, (
        "Recovered verification was not reusable"
    )
    print(f"live attachment crash recovery at {mode} passed")


CRASH_MODES = (
    "before-upload",
    "after-upload",
    "after-mapping",
    "after-delete",
    "lost-checkpoint",
    "orphan-slot",
)


def crash_check(mode: str) -> Callable[[Vault], None]:
    def check(vault: Vault) -> None:
        run_crash_recovery(vault, mode)

    return check


def main() -> None:
    def run_all(vault: Vault) -> None:
        run_checkpoint_test(vault)
        for mode in CRASH_MODES:
            run_crash_recovery(vault, mode)

    vault_main(run_all)


if __name__ == "__main__":
    if len(sys.argv) == 4:
        crash_migration(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        main()
