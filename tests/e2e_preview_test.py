"""Live preview predicts writes while every preview vault mutation is rejected."""

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from unittest.mock import patch

from e2e_checkpoint_test import run_crash
from e2e_vaultwarden_test import run
from pykeepass import create_database

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.convert import Converter
from kp2bw.preview import MigrationPreview
from kp2bw.ssh_mapping import SshRule, parse_ssh_rules


def run_preview_test(tmp: Path, env: dict[str, str], password: str) -> None:
    source = tmp / "preview-live.kdbx"
    db = create_database(source, password="synthetic")
    entry = db.add_entry(db.root_group, "Synthetic preview", "user", "first")
    entry.add_attachment(db.add_binary(b"preview attachment"), "file.txt")
    db.save()
    checkpoint = tmp / "preview-checkpoint.json"
    selected_id: str | None = None
    ssh_rules: list[SshRule] = []

    def converter() -> Converter:
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
            entry_id=selected_id,
            ssh_rules=ssh_rules,
        )

    def preview(expected: str) -> MigrationPreview:
        print(f"Checking read-only preview: {expected}", flush=True)
        source_before = source.read_bytes()
        checkpoint_before = {
            p.name: p.read_bytes() for p in tmp.glob("*checkpoint*") if p.is_file()
        }
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
            original = bw.request

            def read_only(
                method: str,
                path: str,
                *,
                json_body: Mapping[str, Any] | None = None,
                params: dict[str, str] | None = None,
                idempotent: bool | None = None,
            ) -> dict[str, Any]:
                assert method == "GET" or (method == "POST" and path == "/sync"), (
                    "Preview attempted a vault mutation"
                )
                return original(
                    method,
                    path,
                    json_body=json_body,
                    params=params,
                    idempotent=idempotent,
                )

            before = {item["id"]: item.get("revisionDate") for item in bw.list_items()}
            with patch.object(bw, "request", read_only):
                report = converter().preview(bw)
                assert not report.blockers
                assert len(report.entries) == 1
                assert report.entries[0].outcome == expected, (
                    report.entries[0].outcome,
                    report.entries[0].blockers,
                )
                assert not report.entries[0].blockers
                bw.sync(force=True)
                after = {
                    item["id"]: item.get("revisionDate") for item in bw.list_items()
                }
            assert before == after, "Preview changed the vault's inventory or revisions"
        assert source.read_bytes() == source_before
        assert {
            p.name: p.read_bytes() for p in tmp.glob("*checkpoint*") if p.is_file()
        } == checkpoint_before
        return report

    planned = preview("create")
    with patch.dict(os.environ, env):
        assert converter().convert() == 0
    unchanged = preview("unchanged")
    assert planned.entries[0].attachments == unchanged.entries[0].attachments
    assert unchanged.entries[0].uploads == 0
    entry.notes = "source update"
    db.save()
    _ = preview("update")
    with patch.dict(os.environ, env):
        assert converter().convert() == 0
    _ = preview("unchanged")
    entry.attachments[0].id = db.add_binary(b"replacement after interruption")
    db.save()
    planned = preview("update")
    assert planned.entries[0].uploads == 1
    run_crash("after-upload", source, checkpoint, {**env, "BW_TEST_PASSWORD": password})
    resumed = preview("update")
    assert resumed.entries[0].uploads == 0, "Completed upload should be adopted"
    assert resumed.entries[0].attachments == planned.entries[0].attachments
    with patch.dict(os.environ, env):
        assert converter().convert() == 0
    _ = preview("unchanged")
    with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
        listed = bw.get_item_by_uuid(entry.uuid.hex.upper())
        assert listed is not None
        item = bw.get_item(listed["id"])
        item["notes"] = "destination edit"
        bw.update_item(item["id"], item)
    _ = preview("protected")
    unrelated = db.add_entry(db.root_group, "Unrelated SSH ambiguity", "", "")
    unrelated.set_custom_property("Kind", "SSH")
    db.save()
    selected_id = str(entry.uuid)
    ssh_rules = parse_ssh_rules([
        {
            "field": {"name": "Kind", "value": "SSH"},
            "fields": {"privateKey": "Password"},
        },
        {
            "field": {"name": "Title", "value": "Unrelated SSH ambiguity"},
            "fields": {"privateKey": "Password"},
        },
    ])
    _ = preview("protected")
    with patch.dict(os.environ, env):
        assert converter().convert() == 0
    print("live preview predictions and read-only transport checks passed")


def main() -> None:
    env = os.environ.copy()
    env["BITWARDENCLI_APPDATA_DIR"] = env["KP2BW_E2E_BW_PROFILE"]
    env["BW_NOINTERACTION"] = "true"
    status = json.loads(run(["bw", "status"], env=env))
    assert status.get("serverUrl", "").rstrip("/") == env["BW_SERVER_URL"].rstrip("/")
    assert status.get("userEmail", "").casefold() == env["BW_TEST_EMAIL"].casefold()
    with tempfile.TemporaryDirectory() as directory:
        run_preview_test(Path(directory), env, env["BW_TEST_PASSWORD"])


if __name__ == "__main__":
    main()
