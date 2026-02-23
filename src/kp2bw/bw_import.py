"""Build Bitwarden JSON import files and execute ``bw import``."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from subprocess import STDOUT, CalledProcessError, check_output
from typing import Any
from uuid import uuid4

from .exceptions import BitwardenClientError

logger = logging.getLogger(__name__)


def build_import_file(
    entries: dict[str, tuple[str | None, dict[str, Any]]],
) -> dict[str, Any]:
    """Build a Bitwarden JSON import dict from parsed entries.

    *entries* maps KeePass UUIDs to ``(folder_name, bw_item_dict)`` tuples.
    Returns a dict ready for :func:`json.dumps` with ``folders``, ``items``,
    and ``encrypted`` keys conforming to the ``bitwardenjson`` format.

    Synthetic UUIDs are assigned for folder cross-references; the Bitwarden
    importer replaces them with server-assigned IDs on import.
    """
    # Collect unique folder names and assign synthetic UUIDs.
    folder_ids: dict[str, str] = {}
    for folder_name, _item in entries.values():
        if folder_name and folder_name not in folder_ids:
            folder_ids[folder_name] = str(uuid4())

    folders: list[dict[str, str]] = [
        {"id": fid, "name": fname} for fname, fid in folder_ids.items()
    ]

    items: list[dict[str, Any]] = []
    for folder_name, bw_item in entries.values():
        # Shallow copy so we don't mutate the caller's dict.
        item = dict(bw_item)

        # Bind item to its folder via the synthetic UUID.
        if folder_name:
            item["folderId"] = folder_ids[folder_name]
        else:
            item["folderId"] = None

        # Remove transient keys that are not part of the import format.
        item.pop("firstlevel", None)

        items.append(item)

    return {
        "encrypted": False,
        "folders": folders,
        "items": items,
    }


def run_import(filepath: Path) -> None:
    """Execute ``bw import bitwardenjson <filepath>`` as a subprocess."""
    args = ["bw", "import", "bitwardenjson", str(filepath)]
    logger.debug("Running bw import")
    try:
        output = check_output(args, stderr=STDOUT)
        logger.debug(f"bw import returned {len(output)} bytes")
    except CalledProcessError as exc:
        msg = ""
        if isinstance(exc.output, bytes):
            msg = exc.output.decode("utf-8", "ignore")
        raise BitwardenClientError(
            f"bw import failed (exit {exc.returncode}): {msg}"
        ) from exc


def write_and_import(
    entries: dict[str, tuple[str | None, dict[str, Any]]],
) -> None:
    """Build the import file, write to a temp file, import, then delete.

    This is the main entry point for batch import.
    """
    if not entries:
        logger.info("No entries to import")
        return

    import_data = build_import_file(entries)
    item_count = len(import_data["items"])
    folder_count = len(import_data["folders"])
    logger.info(f"Importing {item_count} items across {folder_count} folders")

    # Write to a named temp file so `bw import` can read it by path.
    # delete=False so we control cleanup; the file is removed in finally.
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix="kp2bw-import-",
        delete=False,
    ) as tmp:
        tmp_path = Path(tmp.name)
        json.dump(import_data, tmp, ensure_ascii=False)

    try:
        run_import(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
