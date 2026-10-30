"""Verified reruns avoid attachment bodies; remote changes invalidate the cache."""

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Never
from unittest.mock import patch

from e2e_vaultwarden_test import run
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


def run_crash(mode: str, source: Path, checkpoint: Path, env: dict[str, str]) -> None:
    if os.name != "posix":
        raise AssertionError(
            "Hard-kill integration regression requires POSIX process groups"
        )
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            mode,
            str(source),
            str(checkpoint),
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
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


def remove_uploaded_body(checkpoint: Path, env: dict[str, str], password: str) -> None:
    """Leave a real orphan slot only inside the explicitly selected test container."""
    assert env["BW_SERVER_URL"].startswith("https://localhost:")
    assert env["BW_TEST_EMAIL"] == "integration@example.com"
    records = [
        CheckpointRecord.parse(value)
        for value in json.loads(checkpoint.read_text())["records"]
    ]
    assert len(records) == 1 and records[0].phase == "pending"
    pending = records[0]
    with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
        item = bw.get_item(pending.item_id)
        matches = [
            att["id"]
            for att in item.get("attachments") or []
            if att["id"] not in pending.before_ids
            and hashlib.sha256(att["fileName"].encode()).hexdigest()
            == pending.name_digest
        ]
        assert len(matches) == 1
        assert re.fullmatch(r"[a-zA-Z0-9_-]+", pending.item_id) and re.fullmatch(
            r"[a-zA-Z0-9_-]+", matches[0]
        )
        result = subprocess.run(
            [
                "docker",
                "exec",
                env["KP2BW_E2E_VAULTWARDEN_CONTAINER"],
                "rm",
                "--",
                f"/data/attachments/{pending.item_id}/{matches[0]}",
            ],
            check=False,
            capture_output=True,
            timeout=15,
        )
        assert result.returncode == 0, "Could not remove the synthetic uploaded body"


def run_checkpoint_test(tmp: Path, env: dict[str, str], password: str) -> None:
    source = tmp / "checkpoint.kdbx"
    checkpoint = tmp / "checkpoint.json"
    db = create_database(source, password="synthetic")
    entry = db.add_entry(db.root_group, "Synthetic checkpoint", "", "")
    entry.add_attachment(db.add_binary(b"synthetic checkpoint contents"), "file.txt")
    db.save()
    original_download = BitwardenServeClient.get_attachment
    original_upload = BitwardenServeClient.upload_attachments
    downloads = 0
    uploads = 0

    def download(
        client: BitwardenServeClient, item_id: str, attachment_id: str
    ) -> bytes:
        nonlocal downloads
        downloads += 1
        return original_download(client, item_id, attachment_id)

    def upload(
        client: BitwardenServeClient,
        items: list[tuple[str, list[tuple[str, bytes]]]],
        *,
        max_concurrency: int = 4,
    ) -> list[tuple[str, str]]:
        nonlocal uploads
        uploads += sum(len(files) for _, files in items)
        return original_upload(client, items, max_concurrency=max_concurrency)

    def migrate() -> None:
        with (
            patch.dict(os.environ, env),
            patch.object(BitwardenServeClient, "get_attachment", download),
            patch.object(BitwardenServeClient, "upload_attachments", upload),
        ):
            converter = converter_for(source, checkpoint, password)
            assert converter.convert() == 0

    migrate()
    assert uploads == 1 and downloads > 0
    uploads = downloads = 0
    migrate()
    assert uploads == downloads == 0, (
        "An unchanged verified rerun must not transfer attachment bodies"
    )
    with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
        listed = bw.get_item_by_uuid(entry.uuid.hex.upper())
        assert listed is not None
        item = bw.get_item(listed["id"])
        item["favorite"] = True
        bw.update_item(item["id"], item)
    migrate()
    assert downloads > 0 and uploads == 0, (
        "A changed remote revision must invalidate cached verification"
    )
    uploads = downloads = 0
    migrate()
    assert uploads == downloads == 0
    checkpoint.write_text("{", encoding="utf-8")
    migrate()
    assert downloads > 0 and uploads == 0, (
        "A corrupt checkpoint must safely reverify without reupload"
    )
    modes = [
        "before-upload",
        "after-upload",
        "after-mapping",
        "after-delete",
        "lost-checkpoint",
    ]
    if env.get("KP2BW_E2E_VAULTWARDEN_CONTAINER"):
        modes.append("orphan-slot")
    for mode in modes:
        contents = ("replacement at " + mode).encode()
        entry.attachments[0].id = db.add_binary(contents)
        db.save()
        run_crash(
            "after-upload" if mode in {"orphan-slot", "lost-checkpoint"} else mode,
            source,
            checkpoint,
            {**env, "BW_TEST_PASSWORD": password},
        )
        if mode == "orphan-slot":
            remove_uploaded_body(checkpoint, env, password)
        elif mode == "lost-checkpoint":
            checkpoint.unlink()
        uploads = downloads = 0
        migrate()
        assert uploads == (1 if mode in {"before-upload", "orphan-slot"} else 0), (
            "Recovery repeated a completed byte upload"
        )
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
            listed = bw.get_item_by_uuid(entry.uuid.hex.upper())
            assert listed is not None
            recovered = bw.get_item(listed["id"])
            attachments = recovered.get("attachments") or []
            assert len(attachments) == 1, (
                "Replacement recovery must converge to one mapped file"
            )
            assert bw.get_attachment(recovered["id"], attachments[0]["id"]) == contents
        uploads = downloads = 0
        migrate()
        assert uploads == downloads == 0, "Recovered verification was not reusable"
    print("live attachment checkpoint cache test passed")


def main() -> None:
    env = os.environ.copy()
    env["BITWARDENCLI_APPDATA_DIR"] = env["KP2BW_E2E_BW_PROFILE"]
    env["BW_NOINTERACTION"] = "true"
    status = json.loads(run(["bw", "status"], env=env))
    assert status.get("serverUrl", "").rstrip("/") == env["BW_SERVER_URL"].rstrip("/")
    assert status.get("userEmail", "").casefold() == env["BW_TEST_EMAIL"].casefold()
    with tempfile.TemporaryDirectory() as directory:
        run_checkpoint_test(Path(directory), env, env["BW_TEST_PASSWORD"])


if __name__ == "__main__":
    if len(sys.argv) == 4:
        crash_migration(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        main()
