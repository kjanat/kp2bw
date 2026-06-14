"""Deterministic golden snapshots for the Vaultwarden e2e migration test.

The Bitwarden CLI emits per-item JSON full of volatile fields -- server ids,
revision/creation timestamps, attachment urls and sizes -- that change on every
run.  To assert a migration produced *exactly* the intended vault, this module
normalizes that JSON into a stable, canonically-ordered shape:

* volatile fields are dropped (allowlist: only owned fields are copied),
* folder ids are resolved to folder names,
* each item gets a stable ``token`` derived from ``folder/name`` instead of its
  server id,
* attachment bytes are represented by their sha256 (the bytes are downloaded and
  hashed by the caller and passed in), and
* every list is sorted by a content key.

``canonical_json`` then serializes the result deterministically and
``assert_matches_golden`` compares it against a committed golden file (or
rewrites the golden when ``KP2BW_UPDATE_SNAPSHOTS=1``).

This is deliberately *not* syrupy: the e2e runs as a plain script (``uv run
python tests/e2e_vaultwarden_test.py``) inside Docker / on the runner, not under
pytest, so a fixture-based snapshot library does not fit.  A hand-rolled golden
keeps the diff reviewable in PRs and the dependency surface at zero.
"""

import difflib
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TypedDict

from kp2bw.bw_serve import KP2BW_ID_FIELD_NAME, KP2BW_SYNC_FIELD_NAME

# A concrete recursive type for parsed JSON. Laundering ``json.loads``'s ``Any``
# into this once (``as_object`` / ``parse_object``) means every later
# ``isinstance`` narrows to a fully-known type (e.g. ``dict[str, JsonValue]``)
# rather than ``dict[Unknown, Unknown]`` -- keeping the module strict-clean with
# no ``Any``, ``cast``, or lint suppression.
type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)

# Separates an item id from a file name when keying attachment hashes; NUL never
# appears in a Bitwarden id or a KeePass attachment file name.
ATTACHMENT_KEY_SEP = "\x00"


def attachment_key(item_id: str, file_name: str) -> str:
    """Build the ``attachment_sha256`` map key for one attachment."""
    return f"{item_id}{ATTACHMENT_KEY_SEP}{file_name}"


# --- normalized shapes ------------------------------------------------------


class NormUri(TypedDict):
    uri: str | None
    match: int | None


class NormField(TypedDict):
    name: str | None
    value: str | None
    type: int


class NormFido2(TypedDict):
    credentialId: str | None
    keyType: str | None
    keyAlgorithm: str | None
    keyCurve: str | None
    rpId: str | None
    userName: str | None
    counter: str | None
    discoverable: str | None


class NormLogin(TypedDict):
    username: str | None
    password: str | None
    totp: str | None
    uris: list[NormUri]
    fido2Credentials: list[NormFido2]


class NormAttachment(TypedDict):
    fileName: str | None
    sha256: str


class NormItem(TypedDict):
    token: str
    folder: str | None
    name: str | None
    notes: str | None
    favorite: bool
    type: int
    login: NormLogin | None
    fields: list[NormField]
    attachments: list[NormAttachment]


class NormVault(TypedDict):
    items: list[NormItem]


# --- safe accessors over parsed JSON ----------------------------------------


def as_object(value: JsonValue) -> dict[str, JsonValue]:
    """Narrow a JSON value to an object, or raise."""
    if isinstance(value, dict):
        return value
    raise TypeError(f"expected a JSON object, got {type(value).__name__}")


def parse_object(raw: str) -> dict[str, JsonValue]:
    """Parse a JSON document expected to be an object."""
    data: JsonValue = json.loads(raw)
    return as_object(data)


def _opt_str(m: Mapping[str, JsonValue], key: str) -> str | None:
    value = m.get(key)
    if value is None or isinstance(value, str):
        return value
    raise TypeError(f"field {key!r}: expected string, got {type(value).__name__}")


def _opt_int(m: Mapping[str, JsonValue], key: str) -> int | None:
    value = m.get(key)
    if value is None:
        return None
    # bool is an int subclass; Bitwarden never uses it where an int is expected.
    if isinstance(value, bool):
        raise TypeError(f"field {key!r}: expected int, got bool")
    if isinstance(value, int):
        return value
    raise TypeError(f"field {key!r}: expected int, got {type(value).__name__}")


def _int(m: Mapping[str, JsonValue], key: str, *, default: int) -> int:
    value = _opt_int(m, key)
    return default if value is None else value


def _bool(m: Mapping[str, JsonValue], key: str) -> bool:
    value = m.get(key)
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    raise TypeError(f"field {key!r}: expected bool, got {type(value).__name__}")


def _objects(m: Mapping[str, JsonValue], key: str) -> list[dict[str, JsonValue]]:
    value = m.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return [as_object(entry) for entry in value]
    raise TypeError(f"field {key!r}: expected array, got {type(value).__name__}")


# --- normalization ----------------------------------------------------------


def _norm_uri(raw: Mapping[str, JsonValue]) -> NormUri:
    return {"uri": _opt_str(raw, "uri"), "match": _opt_int(raw, "match")}


def _norm_field(raw: Mapping[str, JsonValue]) -> NormField:
    return {
        "name": _opt_str(raw, "name"),
        "value": _opt_str(raw, "value"),
        "type": _int(raw, "type", default=0),
    }


def _norm_fido2(raw: Mapping[str, JsonValue]) -> NormFido2:
    # ``creationDate`` is derived from the KeePass entry's ctime and is dropped;
    # everything else is content sourced from the KeePass passkey fields.
    return {
        "credentialId": _opt_str(raw, "credentialId"),
        "keyType": _opt_str(raw, "keyType"),
        "keyAlgorithm": _opt_str(raw, "keyAlgorithm"),
        "keyCurve": _opt_str(raw, "keyCurve"),
        "rpId": _opt_str(raw, "rpId"),
        "userName": _opt_str(raw, "userName"),
        "counter": _opt_str(raw, "counter"),
        "discoverable": _opt_str(raw, "discoverable"),
    }


def _norm_login(raw: Mapping[str, JsonValue]) -> NormLogin:
    uris = sorted(
        (_norm_uri(u) for u in _objects(raw, "uris")),
        key=lambda u: (u["uri"] or "", -1 if u["match"] is None else u["match"]),
    )
    creds = sorted(
        (_norm_fido2(c) for c in _objects(raw, "fido2Credentials")),
        key=lambda c: c["credentialId"] or "",
    )
    return {
        "username": _opt_str(raw, "username"),
        "password": _opt_str(raw, "password"),
        "totp": _opt_str(raw, "totp"),
        "uris": uris,
        "fido2Credentials": creds,
    }


def _norm_attachments(
    raw_atts: Sequence[Mapping[str, JsonValue]],
    *,
    item_id: str,
    attachment_sha256: Mapping[str, str],
) -> list[NormAttachment]:
    out: list[NormAttachment] = []
    for att in raw_atts:
        file_name = _opt_str(att, "fileName")
        key = attachment_key(item_id, file_name or "")
        digest = attachment_sha256.get(key)
        if digest is None:
            raise AssertionError(
                f"no sha256 captured for attachment {file_name!r} on item {item_id}"
            )
        out.append({"fileName": file_name, "sha256": digest})
    return sorted(out, key=lambda a: a["fileName"] or "")


def _norm_item(
    raw: Mapping[str, JsonValue],
    *,
    folder_names: Mapping[str, str],
    attachment_sha256: Mapping[str, str],
) -> tuple[str, NormItem]:
    item_id = _opt_str(raw, "id") or ""
    folder_id = _opt_str(raw, "folderId")
    folder = None if folder_id is None else folder_names.get(folder_id, folder_id)

    login_raw = raw.get("login")
    login = _norm_login(login_raw) if isinstance(login_raw, dict) else None

    fields = sorted(
        (
            _norm_field(f)
            for f in _objects(raw, "fields")
            # kp2bw's managed stamps are volatile per run (KP2BW_ID is a KeePass
            # UUID; KP2BW_SYNC is a content hash) and are implementation metadata,
            # not migrated content -- drop them so the golden stays deterministic.
            if f.get("name") not in (KP2BW_ID_FIELD_NAME, KP2BW_SYNC_FIELD_NAME)
        ),
        key=lambda f: (f["name"] or "", f["type"], f["value"] or ""),
    )
    attachments = _norm_attachments(
        _objects(raw, "attachments"),
        item_id=item_id,
        attachment_sha256=attachment_sha256,
    )

    item: NormItem = {
        "token": "",  # filled in by _assign_tokens once collisions are known
        "folder": folder,
        "name": _opt_str(raw, "name"),
        "notes": _opt_str(raw, "notes"),
        "favorite": _bool(raw, "favorite"),
        "type": _int(raw, "type", default=1),
        "login": login,
        "fields": fields,
        "attachments": attachments,
    }
    return item_id, item


def _assign_tokens(pairs: list[tuple[str, NormItem]]) -> None:
    """Assign a stable ``token`` to each item.

    The token is ``folder/name``.  When several items share that base (the seed
    intentionally includes near-duplicate names), a deterministic ``#n`` suffix
    is appended in server-id order.  Idempotent re-runs reuse the same server
    ids, so tokens are stable across passes -- which is what lets ``S1 == S2``
    prove idempotency.
    """
    groups: dict[str, list[tuple[str, NormItem]]] = {}
    for item_id, item in pairs:
        base = f"{item['folder'] or ''}/{item['name'] or ''}"
        groups.setdefault(base, []).append((item_id, item))
    for base, group in groups.items():
        if len(group) == 1:
            group[0][1]["token"] = base
            continue
        for index, (_id, item) in enumerate(sorted(group, key=lambda p: p[0])):
            item["token"] = f"{base}#{index}"


def normalize_vault(
    raw_items: Sequence[Mapping[str, JsonValue]],
    *,
    folder_names: Mapping[str, str],
    attachment_sha256: Mapping[str, str],
) -> NormVault:
    """Normalize raw ``bw get item`` objects into a deterministic vault snapshot."""
    pairs = [
        _norm_item(raw, folder_names=folder_names, attachment_sha256=attachment_sha256)
        for raw in raw_items
    ]
    _assign_tokens(pairs)
    items = sorted(
        (item for _id, item in pairs),
        key=lambda i: (i["folder"] or "", i["name"] or "", i["token"]),
    )
    return {"items": items}


# --- golden comparison ------------------------------------------------------


def env_flag(name: str) -> bool:
    """Whether env var *name* is set to a truthy token (``1``/``true``/``yes``/``on``)."""
    value = os.environ.get(name)
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def canonical_json(vault: NormVault) -> str:
    """Serialize a vault deterministically (sorted keys, UTF-8, ``\\n`` lines)."""
    return json.dumps(vault, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def assert_matches_golden(vault: NormVault, golden_path: Path) -> None:
    """Compare against the golden file, or rewrite it under ``KP2BW_UPDATE_SNAPSHOTS=1``."""
    actual = canonical_json(vault)
    if env_flag("KP2BW_UPDATE_SNAPSHOTS"):
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        _ = golden_path.write_text(actual, encoding="utf-8", newline="\n")
        return
    if not golden_path.exists():
        raise AssertionError(
            f"missing golden snapshot {golden_path}; "
            "regenerate with KP2BW_UPDATE_SNAPSHOTS=1"
        )
    expected = golden_path.read_text(encoding="utf-8")
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                expected.splitlines(keepends=True),
                actual.splitlines(keepends=True),
                fromfile=f"{golden_path.name} (golden)",
                tofile=f"{golden_path.name} (actual)",
            )
        )
        raise AssertionError(f"vault snapshot mismatch for {golden_path.name}:\n{diff}")
