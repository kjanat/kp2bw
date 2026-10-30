"""Explicit IDs must select one source and fail before any destination writes."""

import copy
import shlex
import tempfile
from pathlib import Path
from typing import cast
from unittest import TestCase
from unittest.mock import MagicMock, patch
from uuid import uuid4

from convert_update_test import FakeBw, _as_bw, _make_desired, _make_existing
from pykeepass import create_database

from kp2bw._item_sync import stamp_content
from kp2bw._selection import resolve_selection
from kp2bw.bw_types import BwItemResponse
from kp2bw.cli import _argparser
from kp2bw.convert import Converter
from kp2bw.exceptions import ConversionError


def converter(
    path: Path, entry_id: str | None, item_id: str | None = None
) -> Converter:
    return Converter(
        keepass_file_path=str(path),
        keepass_password="synthetic",
        keepass_keyfile_path=None,
        bitwarden_password="never-log-this",
        bitwarden_organization_id=None,
        bitwarden_coll_id=None,
        path2name=False,
        path2nameskip=1,
        import_tags=None,
        entry_id=entry_id,
        item_id=item_id,
    )


def main() -> None:
    for invalid in ("", "not-a-uuid"):
        try:
            converter(Path("unused.kdbx"), invalid)
        except ConversionError:
            pass
        else:
            raise AssertionError("Invalid selector fell back to a full migration")
    source, destination = str(uuid4()), str(uuid4())
    item = cast(
        BwItemResponse,
        {
            "id": destination,
            "type": 1,
            "fields": [{"name": "KP2BW_ID", "value": source, "type": 0}],
        },
    )
    selected = resolve_selection(source, destination, [item], {destination})
    assert selected.source_id == source.replace("-", "").upper()
    assert selected.destination_id == destination
    assert resolve_selection(None, destination, [item], {destination}) == selected
    assert resolve_selection(source, None, [], set()).destination_id is None
    for requested_source, requested_destination, items, scope in (
        (source, destination, [item], set[str]()),
        (source, str(uuid4()), [item], {destination}),
        (str(uuid4()), destination, [item], {destination}),
        (source, None, [item, item], {destination}),
        ("invalid", None, [], set[str]()),
        (source, "invalid", [], set[str]()),
    ):
        try:
            resolve_selection(requested_source, requested_destination, items, scope)
        except ConversionError:
            pass
        else:
            raise AssertionError("Unsafe selector accepted")
    for fields in ([], [*item["fields"], *item["fields"]]):
        invalid = copy.deepcopy(item)
        invalid["fields"] = fields
        try:
            resolve_selection(None, destination, [invalid], {destination})
        except ConversionError:
            pass
        else:
            raise AssertionError("Non-unique association accepted")

    conv = converter(Path("synthetic.kdbx"), source)
    existing = _make_existing(id=destination)
    existing["fields"].append({"name": "KP2BW_ID", "value": source, "type": 0})
    desired = _make_desired(notes="source change")
    with TestCase().assertLogs("kp2bw.convert", level="WARNING") as logs:
        outcome, _, _ = conv._reconcile_existing_item(
            _as_bw(FakeBw(fail_update=True)),
            existing,
            None,
            desired,
            [],
            fixed_coll_id=None,
            kp_uuid=source,
        )
    assert outcome == "failed"
    diagnostic = " ".join(logs.output)
    assert source in diagnostic and destination in diagnostic
    assert "--force-update" not in diagnostic and "never-log-this" not in diagnostic
    legacy = _make_existing(id=destination)
    with TestCase().assertLogs("kp2bw.convert", level="WARNING") as logs:
        outcome, _, _ = conv._reconcile_existing_item(
            _as_bw(FakeBw(fail_update=True)),
            legacy,
            None,
            desired,
            [],
            fixed_coll_id=None,
            kp_uuid=source,
            force_update=True,
        )
    assert outcome == "failed"
    diagnostic = " ".join(logs.output)
    assert "--entry-id" not in diagnostic and "--item-id" not in diagnostic
    assert "Retry" in diagnostic
    stamp_content(existing)
    existing["notes"] = "destination edit"
    with TestCase().assertLogs("kp2bw.convert", level="WARNING") as logs:
        outcome, _, _ = conv._reconcile_existing_item(
            _as_bw(FakeBw()),
            existing,
            None,
            desired,
            [],
            fixed_coll_id=None,
            kp_uuid=source,
        )
    assert outcome == "protected"
    diagnostic = " ".join(logs.output)
    assert source in diagnostic and destination in diagnostic
    assert "--force-update" in diagnostic and "never-log-this" not in diagnostic

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "selection.kdbx"
        db = create_database(path, password="synthetic")
        target = db.add_entry(db.root_group, "Same title", "user", "password")
        alias = db.add_entry(
            db.root_group,
            "Same title",
            "user",
            f"{{REF:P@I:{target.uuid.hex.upper()}}}",
            force_creation=True,
        )
        alias.url = "https://alias.example.test"
        alias.otp = "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP"
        chain = db.add_entry(
            db.root_group,
            "Chained alias",
            "user",
            f"{{REF:P@I:{alias.uuid.hex.upper()}}}",
        )
        chain.url = "https://chain.example.test"
        unrelated = db.add_entry(db.root_group, "Unrelated", "u", "p")
        unrelated.tags = ["elsewhere"]
        db.save()
        client = MagicMock()
        client.__enter__.return_value = client
        client.list_items.return_value = []
        conv = converter(path, str(alias.uuid))
        with (
            patch("kp2bw.convert.BitwardenServeClient", return_value=client),
            patch.object(
                conv, "_create_bitwarden_items_for_entries", return_value=0
            ) as write,
        ):
            assert conv.convert() == 0
            write.assert_called_once_with(client)
            assert set(conv._entries) == {alias.uuid.hex.upper()}
            result = next(iter(conv._entries.values()))[2]
            assert result["login"]["password"] == "password"
            assert result["name"] == "Same title"
        full = converter(path, None)
        full._load_keepass_data()
        full._resolve_entries_with_references()
        full_target = full._unpack_entry(full._entries[target.uuid.hex.upper()])[2]
        conv = converter(path, str(target.uuid))
        with (
            patch("kp2bw.convert.BitwardenServeClient", return_value=client),
            patch.object(conv, "_create_bitwarden_items_for_entries", return_value=0),
        ):
            assert conv.convert() == 0
        assert set(conv._entries) == {target.uuid.hex.upper()}
        selected_target = conv._unpack_entry(conv._entries[target.uuid.hex.upper()])[2]
        assert selected_target["login"] == full_target["login"]
        assert selected_target["login"]["totp"]
        assert {uri["uri"] for uri in selected_target["login"]["uris"]} >= {
            "https://alias.example.test",
            "https://chain.example.test",
        }
        for source_id, tags in ((str(uuid4()), None), (str(alias.uuid), ["elsewhere"])):
            conv = converter(path, source_id)
            conv._import_tags = tags
            with (
                patch("kp2bw.convert.BitwardenServeClient", return_value=client),
                patch.object(conv, "_create_bitwarden_items_for_entries") as write,
            ):
                try:
                    conv.convert()
                except ConversionError:
                    pass
                else:
                    raise AssertionError("Unknown/filtered source accepted")
                write.assert_not_called()
        conv = converter(path, str(alias.uuid))
        command = conv._retry_item(str(alias.uuid), destination, force=True)
        assert "never-log-this" not in command and "synthetic" not in command
        args = _argparser().parse_args(shlex.split(command)[1:])
        assert args.entry_id == str(alias.uuid) and args.item_id == destination
        assert args.force_update and args.path_to_name is False
        assert "--force-update" not in conv._retry_item(str(alias.uuid), destination)
        conv._keepass_file_path = "someone's vault.kdbx"
        with patch("kp2bw.convert.os.name", "nt"):
            command = conv._retry_item(str(alias.uuid), destination)
        assert command.startswith("& 'kp2bw'")
        assert "'someone''s vault.kdbx'" in command
    print("item selection and preflight tests passed")


if __name__ == "__main__":
    main()
