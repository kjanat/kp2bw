"""Preview uses real conversion without opening a destination or exposing values."""

import copy
import io
import json
import os
import tempfile
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

from attachment_checkpoint_test import record, scope
from convert_update_test import UpdateTestConverter, make_desired, make_existing
from pykeepass import create_database

from kp2bw.attachment_capability import AttachmentCapability, attachment_capability
from kp2bw.attachment_resume import transaction_filename
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse
from kp2bw.checkpoint import AttachmentCheckpoint
from kp2bw.cli import main as cli_main
from kp2bw.cli_policy_state import CliPolicyState
from kp2bw.convert import Converter
from kp2bw.exceptions import BitwardenClientError
from kp2bw.item_sync import stamp_content
from kp2bw.preview import PreviewEntry, describe_payload
from kp2bw.preview_transport import PreviewCheckpoint, PreviewTransport
from kp2bw.ssh_mapping import parse_ssh_rules


def check_target_reconciliation() -> None:
    for condition in ("unchanged", "changed", "protected", "unsupported"):
        existing = make_existing(revisionDate="revision")
        stamp_content(existing)
        desired = make_desired()
        if condition in {"changed", "protected", "unsupported"}:
            desired["notes"] = "new source notes"
        if condition == "protected":
            existing["notes"] = "manual destination edit"
        original = copy.deepcopy(existing)

        def read(item_id: str, existing: BwItemResponse = existing) -> BwItemResponse:
            return copy.deepcopy(existing)

        def attachment(item_id: str, attachment_id: str) -> bytes:
            raise AssertionError("This fixture has no attachment reads")

        def validate(
            item_id: str, payload: BwItemResponse, condition: str = condition
        ) -> None:
            if condition == "unsupported":
                raise BitwardenClientError("Unsupported synthetic capability")

        transport = PreviewTransport(read, attachment, validate)
        outcome, uploads, stale = UpdateTestConverter().reconcile(
            transport, existing, None, desired, [], fixed_coll_id=None
        )
        assert (
            outcome
            == {
                "unchanged": "skipped",
                "changed": "updated",
                "protected": "protected",
                "unsupported": "failed",
            }[condition]
        )
        assert bool(transport.updated_ids) == (condition == "changed")
        assert not uploads and not stale
        assert existing == original, "Preview changed its source destination snapshot"
        try:
            transport.request("DELETE", "/object/item/synthetic")
        except BitwardenClientError:
            pass
        else:
            raise AssertionError("Preview allowed a direct transport mutation")


def check_checkpoint_snapshot() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "checkpoint.json"
        missing = PreviewCheckpoint(path, scope())
        missing.save(record())
        assert not list(Path(directory).iterdir())
        with AttachmentCheckpoint(path, scope()) as checkpoint:
            checkpoint.save(record())
        before = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
        preview = PreviewCheckpoint(path, scope())
        assert preview.records[record().key] == record()
        preview.save(replace(record(), remote_revision="predicted"))
        assert preview.records[record().key].remote_revision == "predicted"
        assert {p.name: p.read_bytes() for p in Path(directory).iterdir()} == before
        item = make_existing(attachments=[{"id": "orphan", "fileName": "file"}])
        original = copy.deepcopy(item)
        transport = PreviewTransport(
            lambda _: item,
            lambda unused_item, attachment: b"",
            lambda unused_item, payload: None,
        )
        transport.delete_attachment(item["id"], "orphan")
        transport.sync(force=True)
        assert transport.get_item(item["id"]).get("attachments") == []
        assert item == original
        assert transport.deleted_attachments == {(item["id"], "orphan")}


def main() -> None:
    for arguments in (
        ["--preview", "--fixup"],
        ["--entry-id", "00000000-0000-0000-0000-000000000001", "--fixup"],
    ):
        with (
            patch("sys.argv", ["kp2bw", *arguments]),
            patch("kp2bw.cli.load_dotenv", return_value=None),
            patch("kp2bw.cli.configure_logging", return_value=None),
            patch(
                "kp2bw.cli.ensure_bw_available",
                side_effect=AssertionError("Invalid modes opened Bitwarden"),
            ),
        ):
            try:
                cli_main()
            except SystemExit as exc:
                assert exc.code == 2
            else:
                raise AssertionError("Preview/selection accepted a mutation-only mode")
    check_checkpoint_snapshot()
    native = make_desired(type=3, card={"number": "private-card-number"})
    native_report = PreviewEntry("source", "planned")
    describe_payload(native_report, native, [])
    assert "card.number" in native_report.native_fields
    assert not any(name.startswith("login.") for name in native_report.native_fields)
    assert "private-card-number" not in repr(native_report)
    denied = CliPolicyState("bitwarden", "https://synthetic.example/api", (), (), False)
    assert attachment_capability(denied, None).allowed is False
    assert attachment_capability(denied, "absent").allowed is None
    for maximum, allowed in ((0, False), (1, True), (None, None), (-1, None)):
        state = CliPolicyState(
            "vaultwarden",
            "https://synthetic.example/api",
            ({"id": "org", "status": 2, "maxStorageGb": maximum},),
            (),
        )
        capability = attachment_capability(state, "org")
        assert capability.allowed is allowed
        assert capability.free_storage_bytes is None
    check_target_reconciliation()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "preview.kdbx"
        db = create_database(path, password="synthetic")
        entry = db.add_entry(
            db.root_group, "Example", "private-user", "private-password"
        )
        entry.set_custom_property("secret", "private-field", protect=True)
        entry.notes = "n" * 8000
        entry.add_attachment(db.add_binary(b"private-file-body"), "notes.txt")
        group_notes = db.root_group._element.find("Notes")
        assert group_notes is not None
        group_notes.text = "private-group-notes"
        sequence = entry._element.find("AutoType/DefaultSequence")
        assert sequence is not None
        sequence.text = "private-autotype-sequence"
        db.save()
        before = path.read_bytes()
        converter = Converter(
            str(path), "synthetic", None, "", None, None, False, 999, None
        )
        with patch(
            "kp2bw.convert.BitwardenServeClient",
            side_effect=AssertionError("Preview opened the destination"),
        ):
            preview = converter.preview()
        report = preview.to_dict()
        encoded = json.dumps(report)
        for secret in (
            "private-user",
            "private-password",
            "private-field",
            "private-file-body",
            "private-group-notes",
            "private-autotype-sequence",
            "n" * 100,
        ):
            assert secret not in encoded
        assert path.read_bytes() == before
        assert not preview.blockers
        assert len(preview.entries) == 1
        planned = preview.entries[0]
        assert planned.outcome == "planned"
        assert planned.custom_fields == planned.hidden_fields == 1
        assert any("autotype_sequences" in reason for reason in planned.omissions)
        assert preview.groups[0].omitted["notes"] == 1
        assert len(planned.attachments) == 2
        assert len({a.filename for a in planned.attachments}) == 2
        assert sum(a.bytes for a in planned.attachments) == 8000 + len(
            b"private-file-body"
        )
        assert {a.kind for a in planned.attachments} == {"notes", "original"}
        # The plan is the metadata projection of the same payload preparation
        # used by execution, including collision resolution for generated files.
        actual = next(iter(converter.entries.values()))
        files = converter.attachment_sources(actual[3])
        assert [(a.filename, a.bytes) for a in planned.attachments] == [
            (a.filename, len(a.data)) for a in files
        ]
        remote = cast(
            BwItemResponse,
            {
                **copy.deepcopy(actual[2]),
                "id": "destination",
                "revisionDate": "revision",
            },
        )
        target = MagicMock(spec=BitwardenServeClient)
        target.item_policy_blockers.return_value = {}
        target.attachment_capability.return_value = AttachmentCapability(True)
        target.list_items.return_value = [remote]
        target.list_folders.return_value = {}
        target.get_item.return_value = remote
        compared = converter.preview(cast(BitwardenServeClient, target))
        assert compared.target_inspected
        assert compared.entries[0].outcome == "update"
        assert compared.entries[0].uploads == 2
        target.attachment_capability.return_value = AttachmentCapability(
            False, reason="No upload entitlement"
        )
        denied_plan = converter.preview(cast(BitwardenServeClient, target))
        assert denied_plan.entries[0].outcome == "blocked"
        assert "No upload entitlement" in denied_plan.entries[0].blockers
        target.attachment_capability.return_value = AttachmentCapability(True)
        target.item_policy_blockers.return_value = {
            1: "Organization policy forbids login items"
        }
        restricted_plan = converter.preview(cast(BitwardenServeClient, target))
        assert restricted_plan.entries[0].outcome == "blocked"
        assert restricted_plan.entries[0].blockers == [
            "Organization policy forbids login items"
        ]
        target.item_policy_blockers.return_value = {}
        for mutation in (
            target.update_item,
            target.update_item_if_revision,
            target.create_item,
            target.delete_attachment,
            target.upload_attachments,
            target.create_org_collection,
        ):
            mutation.assert_not_called()
        target.list_items.return_value = [remote, {**remote, "id": "duplicate"}]
        ambiguous = converter.preview(cast(BitwardenServeClient, target))
        assert ambiguous.entries[0].outcome == "blocked"
        assert ambiguous.entries[0].blockers
        output = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sys.argv", ["kp2bw", str(path), "--preview", "json"]),
            patch("kp2bw.cli.load_dotenv", return_value=None),
            patch("kp2bw.cli.configure_logging", return_value=None),
            patch("kp2bw.cli.read_password", return_value="synthetic") as passwords,
            patch(
                "kp2bw.cli.ensure_bw_available",
                side_effect=AssertionError("Preview required bw"),
            ),
            patch(
                "kp2bw.convert.BitwardenServeClient",
                side_effect=AssertionError("Preview opened bw"),
            ),
            redirect_stdout(output),
        ):
            cli_main()
        passwords.assert_called_once()
        cli_report = json.loads(output.getvalue())
        assert cli_report["target_inspected"] is False
        assert cli_report["summary"]["attachments"] == 2
        assert cli_report["entries"][0]["source_id"] == entry.uuid.hex.upper()
        assert path.read_bytes() == before
        target.list_items.return_value = []
        target.__enter__.return_value = target
        output = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "sys.argv",
                [
                    "kp2bw",
                    str(path),
                    "--preview",
                    "json",
                    "--preview-target",
                    "-o",
                    "organization",
                    "-c",
                    "collection",
                ],
            ),
            patch("kp2bw.cli.load_dotenv", return_value=None),
            patch("kp2bw.cli.configure_logging", return_value=None),
            patch(
                "kp2bw.cli.read_password",
                side_effect=["synthetic", "destination-password"],
            ),
            patch("kp2bw.cli.ensure_bw_available") as availability,
            patch("kp2bw.cli.BitwardenServeClient", return_value=target) as client,
            redirect_stdout(output),
        ):
            cli_main()
        availability.assert_called_once()
        client.assert_called_once_with(
            "destination-password", org_id="organization", collection_id="collection"
        )
        target.list_items.assert_called_with(
            organization_id="organization", collection_id="collection"
        )
        target_report = json.loads(output.getvalue())
        assert target_report["target_inspected"] is True
        assert target_report["entries"][0]["outcome"] == "create"
        target.create_item.assert_not_called()
        target.upload_attachments.assert_not_called()
        invalid = db.add_entry(
            db.root_group, "Invalid budget", "private-overlimit" * 60, "pw"
        )
        unresolved = db.add_entry(
            db.root_group,
            "Missing reference",
            "{REF:U@I:00000000000000000000000000000001}",
            "pw",
        )
        db.save()
        partial = converter.preview()
        by_id = {e.source_id: e for e in partial.entries}
        assert by_id[entry.uuid.hex.upper()].outcome == "planned"
        invalid_plan = by_id[invalid.uuid.hex.upper()]
        assert invalid_plan.outcome == "blocked"
        assert any("Login username" in reason for reason in invalid_plan.blockers)
        assert by_id[unresolved.uuid.hex.upper()].outcome == "unresolved"
        assert by_id[unresolved.uuid.hex.upper()].blockers
        assert "private-overlimit" not in json.dumps(partial.to_dict())
        selected = Converter(
            str(path),
            "synthetic",
            None,
            "",
            None,
            None,
            False,
            999,
            None,
            entry_id=str(entry.uuid),
            checkpoint_path=str(Path(directory) / "resume.json"),
        )
        selected_plan = selected.preview()
        assert len(selected_plan.entries) == 1
        assert selected_plan.entries[0].outcome == "planned"
        assert all(not a.filename_final for a in selected_plan.entries[0].attachments)
        target.checkpoint_identity.return_value = (
            "https://synthetic.example",
            "account",
        )
        target.list_items.return_value = []
        snapshot = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
        created = selected.preview(cast(BitwardenServeClient, target))
        assert created.entries[0].outcome == "create"
        from kp2bw.checkpoint import CheckpointScope

        digest = CheckpointScope(
            "https://synthetic.example", "account", selected.source_scope_id
        ).digest
        sources = selected.attachment_sources(
            selected.entries[entry.uuid.hex.upper()][3]
        )
        assert [a.filename for a in created.entries[0].attachments] == [
            transaction_filename(source, digest, entry.uuid.hex.upper(), None)
            for source in sources
        ]
        assert all(a.filename_final for a in created.entries[0].attachments)
        assert {p.name: p.read_bytes() for p in Path(directory).iterdir()} == snapshot
        remote["id"] = "11111111-1111-4111-8111-111111111111"
        target.list_items.return_value = [remote]
        by_destination = Converter(
            str(path),
            "synthetic",
            None,
            "",
            None,
            None,
            False,
            999,
            None,
            item_id=remote["id"],
        ).preview(cast(BitwardenServeClient, target))
        assert len(by_destination.entries) == 1
        assert by_destination.entries[0].source_id == entry.uuid.hex.upper()
        assert by_destination.entries[0].target_id == remote["id"]
        entry.set_custom_property("Type", "SSH")
        entry.set_custom_property("Private Key", "private-invalid-key", protect=True)
        db.save()
        fallback = Converter(
            str(path),
            "synthetic",
            None,
            "",
            None,
            None,
            False,
            999,
            None,
            entry_id=str(entry.uuid),
            ssh_rules=parse_ssh_rules([
                {
                    "field": {"name": "Type", "value": "SSH"},
                    "fields": {"privateKey": "Private Key"},
                }
            ]),
        ).preview()
        assert fallback.entries[0].outcome == "blocked"
        assert fallback.entries[0].item_type == 1
        assert any("SSH" in reason for reason in fallback.entries[0].blockers)
        assert "private-invalid-key" not in json.dumps(fallback.to_dict())
        duplicate = db.add_entry(db.root_group, "Duplicate", "", "")
        duplicate.uuid = entry.uuid
        db.save()
        duplicate_report = converter.preview()
        duplicate_entry = next(
            e for e in duplicate_report.entries if e.source_id == entry.uuid.hex.upper()
        )
        assert duplicate_entry.outcome == "blocked"
        assert any("share this UUID" in reason for reason in duplicate_entry.blockers)
    print("source preview preserves secrets and performs no destination operations")


if __name__ == "__main__":
    main()
