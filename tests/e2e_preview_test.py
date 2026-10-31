"""Live preview predicts writes while every preview vault mutation is rejected."""

from collections.abc import Mapping
from typing import Any
from unittest.mock import patch

from e2e_checkpoint_test import run_crash
from e2e_support import Vault, vault_main
from pykeepass import create_database

from kp2bw.convert import Converter
from kp2bw.preview import MigrationPreview
from kp2bw.ssh_mapping import SshRule, parse_ssh_rules


class PreviewFixture:
    def __init__(self, vault: Vault, name: str) -> None:
        self.vault = vault
        self.source = vault.tmp / f"{name}.kdbx"
        self.checkpoint = vault.tmp / f"{name}-checkpoint.json"
        self.db = create_database(self.source, password="synthetic")
        self.entry = self.db.add_entry(
            self.db.root_group, "Synthetic preview", "user", "first"
        )
        self.entry.add_attachment(self.db.add_binary(b"preview attachment"), "file.txt")
        self.db.save()
        self.selected_id: str | None = None
        self.ssh_rules: tuple[SshRule, ...] = ()

    def converter(self) -> Converter:
        return Converter(
            str(self.source),
            "synthetic",
            None,
            self.vault.password,
            None,
            None,
            False,
            999,
            None,
            migrate_metadata=False,
            checkpoint_path=str(self.checkpoint),
            entry_id=self.selected_id,
            ssh_rules=self.ssh_rules,
        )

    def convert(self) -> None:
        assert self.converter().convert(self.vault.client) == 0

    def checkpoints(self) -> dict[str, bytes]:
        return {
            p.name: p.read_bytes()
            for p in self.vault.tmp.glob("*checkpoint*")
            if p.is_file()
        }

    def preview(self, expected: str) -> MigrationPreview:
        print(f"Checking read-only preview: {expected}", flush=True)
        source_before = self.source.read_bytes()
        checkpoint_before = self.checkpoints()
        bw = self.vault.fresh()
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
            report = self.converter().preview(bw)
            assert not report.blockers
            assert len(report.entries) == 1
            assert report.entries[0].outcome == expected, (
                report.entries[0].outcome,
                report.entries[0].blockers,
            )
            assert not report.entries[0].blockers
            bw.sync(force=True)
            after = {item["id"]: item.get("revisionDate") for item in bw.list_items()}
        assert before == after, "Preview changed the vault's inventory or revisions"
        assert self.source.read_bytes() == source_before
        assert self.checkpoints() == checkpoint_before
        return report


def run_preview_test(vault: Vault) -> None:
    fixture = PreviewFixture(vault, "preview-live")
    planned = fixture.preview("create")
    fixture.convert()
    unchanged = fixture.preview("unchanged")
    assert planned.entries[0].attachments == unchanged.entries[0].attachments
    assert unchanged.entries[0].uploads == 0
    fixture.entry.notes = "source update"
    fixture.db.save()
    _ = fixture.preview("update")
    fixture.convert()
    _ = fixture.preview("unchanged")
    item = vault.item(fixture.entry.uuid.hex.upper())
    item["notes"] = "destination edit"
    vault.client.update_item(item["id"], item)
    _ = fixture.preview("protected")
    unrelated = fixture.db.add_entry(
        fixture.db.root_group, "Unrelated SSH ambiguity", "", ""
    )
    unrelated.set_custom_property("Kind", "SSH")
    fixture.db.save()
    fixture.selected_id = str(fixture.entry.uuid)
    fixture.ssh_rules = parse_ssh_rules([
        {
            "field": {"name": "Kind", "value": "SSH"},
            "fields": {"privateKey": "Password"},
        },
        {
            "field": {"name": "Title", "value": "Unrelated SSH ambiguity"},
            "fields": {"privateKey": "Password"},
        },
    ])
    _ = fixture.preview("protected")
    fixture.convert()
    print("live preview predictions and read-only transport checks passed")


def run_preview_resume_test(vault: Vault) -> None:
    fixture = PreviewFixture(vault, "preview-resume")
    fixture.convert()
    fixture.entry.attachments[0].id = fixture.db.add_binary(
        b"replacement after interruption"
    )
    fixture.db.save()
    planned = fixture.preview("update")
    assert planned.entries[0].uploads == 1
    run_crash("after-upload", fixture.source, fixture.checkpoint, vault)
    resumed = fixture.preview("update")
    assert resumed.entries[0].uploads == 0, "Completed upload should be adopted"
    assert resumed.entries[0].attachments == planned.entries[0].attachments
    fixture.convert()
    _ = fixture.preview("unchanged")
    print("live preview of an interrupted replacement passed")


def main() -> None:
    def run_all(vault: Vault) -> None:
        run_preview_test(vault)
        run_preview_resume_test(vault)

    vault_main(run_all)


if __name__ == "__main__":
    main()
