import base64
import binascii
import copy
import hashlib
import json
import logging
import os
import re
import shlex
import time
from collections.abc import Mapping
from contextlib import ExitStack, nullcontext
from dataclasses import dataclass, replace
from itertools import islice
from pathlib import Path
from typing import Literal
from uuid import UUID

import yaml
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pykeepass import Attachment, Entry, Group, PyKeePass
from pykeepass.exceptions import (
    CredentialsError,
    HeaderChecksumError,
    PayloadChecksumError,
)
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from . import VERBOSE
from ._attachment_capability import AttachmentCapability
from ._attachment_resume import inspect_pending_upload, transaction_filename
from ._attachments import (
    ATTACHMENT_FIELD_PREFIX,
    AttachmentPlan,
    FileRecord,
    SourceFile,
    fields_from_records,
    is_record_field,
    plan_attachments,
    records_from_fields,
    source_file,
)
from ._checkpoint import (
    AttachmentCheckpoint,
    CheckpointRecord,
    CheckpointScope,
    metadata_digest,
)
from ._console import console
from ._field_limits import (
    FIELD_VALUE_LIMIT,
    NAME_LIMIT,
    NOTES_LIMIT,
    fits_field,
    require_field,
    validate_item,
)
from ._history import (
    HISTORY_FIELD_NAME,
    apply_native_history,
    has_managed_history,
    history_archive,
    imported_history_count,
    native_password_history,
)
from ._item_sync import (
    KP2BW_ID_FIELD_NAME,
    KP2BW_SYNC_FIELD_NAME,
    content_signature,
    fields_signature,
    legacy_extensions_differ,
    login_signature,
    mark_credential_id,
    stamp_content,
    sync_stamp_generation,
    sync_stamp_matches,
)
from ._preview import (
    MigrationPreview,
    PreviewEntry,
    PreviewGroup,
    describe_attachments,
    describe_payload,
    group_inventory,
    source_inventory,
)
from ._preview_transport import PreviewCheckpoint, PreviewTransport
from ._selection import ItemSelection, resolve_selection, source_uuid
from ._source_fields import source_field_name, source_field_origin
from ._ssh_mapping import SshRule, apply_ssh_rule
from ._templates import TemplateRule, apply_template, recognize_template, template_uuid
from .bw_serve import (
    BitwardenServeClient,
    item_kp2bw_id,
    item_kp2bw_sync,
)
from .bw_types import (
    BwFido2Credential,
    BwField,
    BwItemCreate,
    BwItemLogin,
    BwItemResponse,
    BwUri,
)
from .exceptions import (
    BitwardenAttachmentMissingError,
    BitwardenClientError,
    ConversionError,
    FieldLimitError,
)
from .otp import OtpMigration, is_otp_secret_field, resolve_otp, totp_values_equivalent
from .uri_mapping import (
    UriMatchValue,
    build_login_uris,
    is_android_app_key,
    is_url_attribute_key,
    match_value_names,
    parse_match_name,
    url_attribute_index,
)

logger = logging.getLogger(__name__)

KP_REF_IDENTIFIER: str = "{REF:"
KPEX_PASSKEY_PREFIX: str = "KPEX_PASSKEY_"
# Bitwarden item type for login entries (1=login, 2=secureNote, 3=card,
# 4=identity). Explicit template mapping is applied after REF resolution.
BW_ITEM_TYPE_LOGIN: int = 1
AUTO_COLLECTION_MODE: str = "auto"
NESTED_COLLECTION_MODE: str = "nested"
COLLECTION_FOLDER_MODES: frozenset[str] = frozenset({
    AUTO_COLLECTION_MODE,
    NESTED_COLLECTION_MODE,
})

# Single custom field holding KeePass metadata Bitwarden has no native slot for
# (tags, expiry) as JSON. Folds what used to be several rows into one,
# and is omitted entirely when an entry has no such metadata.
KP2BW_META_FIELD_NAME: str = "KP2BW_META"

# Mirrors pykeepass.entry.reserved_keys. Custom-property access in supported
# PyKeePass versions interpolates keys into XPath, so enumerate the XML once
# instead of calling Entry.custom_properties for untrusted field names.
_KEEPASS_RESERVED_STRING_KEYS: frozenset[str] = frozenset({
    "Title",
    "UserName",
    "Password",
    "URL",
    "Tags",
    "IconID",
    "Times",
    "History",
    "Notes",
    "otp",
})

# Attachment-like: real pykeepass Attachment or (key, value) tuple for long fields
type AttachmentItem = Attachment | tuple[str, str] | SourceFile

# Entry storage: (folder, firstlevel, bw_item, attachments)
type EntryValue = tuple[str | None, str | None, BwItemCreate, list[AttachmentItem]]

# Custom field spec: (value, type_int)  e.g. ("secret", 1)
# Field types: 0=text, 1=hidden, 2=boolean, 3=linked
type FieldSpec = tuple[str | None, Literal[0, 1, 2, 3]]


@dataclass(frozen=True)
class _EntryCustomProperties:
    """Custom values and memory-protection flags read in one XML traversal."""

    values: dict[str, str | None]
    protected_keys: frozenset[str]


@dataclass
class _LegacyRefState:
    """Exact item shape and stale stamp emitted by the pre-fix REF flow."""

    initial_sync_stamp: str
    item: BwItemCreate
    base_uris: list[BwUri]
    uri_merges: dict[int, list[BwUri]]


def _read_entry_custom_properties(entry: Entry) -> _EntryCustomProperties:
    """Read custom fields without placing attacker-controlled keys in XPath."""
    values: dict[str, str | None] = {}
    protected_keys: set[str] = set()
    occurrences: dict[str, int] = {}

    for string_element in entry._element.findall("String"):
        key_element = string_element.find("Key")
        key = key_element.text if key_element is not None else None
        if key is None or key in _KEEPASS_RESERVED_STRING_KEYS:
            continue

        occurrences[key] = occurrences.get(key, 0) + 1
        original_key = key
        key = source_field_name(key, occurrences[key])
        value_element = string_element.find("Value")
        values[key] = value_element.text if value_element is not None else None
        if (
            value_element is not None
            and value_element.attrib.get("Protected", "False") == "True"
        ):
            protected_keys.add(key)
        if key != original_key and (
            is_otp_secret_field(original_key)
            or original_key.startswith(KPEX_PASSKEY_PREFIX)
        ):
            protected_keys.add(key)

    return _EntryCustomProperties(values, frozenset(protected_keys))


def _print_summary(
    elapsed: float,
    n_created: int,
    n_updated: int,
    n_skipped: int,
    n_protected: int,
    n_collection_update: int,
    n_attachments: int,
    n_update_failed: int,
    n_attach_failed: int,
    n_create_failed: int,
    n_history: int = 0,
) -> None:
    """Print a final migration summary to the shared rich console."""
    m, s = divmod(int(elapsed), 60)
    duration = f"{m}m {s:02d}s" if m else f"{s}s"
    console.print(f"\nDone in [bold]{duration}[/bold]")
    w = len(
        str(
            max(
                n_created,
                n_updated,
                n_skipped,
                n_protected,
                n_collection_update,
                n_attachments,
                n_update_failed,
                n_attach_failed,
                n_create_failed,
                n_history,
                1,
            )
        )
    )
    console.print(f"  [green]{n_created:{w}d}[/green] created")
    if n_updated:
        console.print(f"  [blue]{n_updated:{w}d}[/blue] updated (changed in KeePass)")
    if n_skipped:
        console.print(f"  [dim]{n_skipped:{w}d}[/dim] skipped (unchanged)")
    if n_protected:
        console.print(
            f"  [magenta]{n_protected:{w}d}[/magenta] protected (edited in "
            f"Bitwarden; see the item-specific retry above)"
        )
    if n_collection_update:
        console.print(
            f"  [yellow]{n_collection_update:{w}d}[/yellow] added to collection"
        )
    if n_attachments:
        console.print(f"  [cyan]{n_attachments:{w}d}[/cyan] attachments uploaded")
    if n_history:
        console.print(f"  [cyan]{n_history:{w}d}[/cyan] previous passwords imported")
    if n_create_failed:
        console.print(
            f"  [red]{n_create_failed:{w}d}[/red] entries failed to create "
            f"(see warnings above)"
        )
    if n_update_failed:
        console.print(
            f"  [red]{n_update_failed:{w}d}[/red] entries failed to update "
            f"(see warnings above)"
        )
    if n_attach_failed:
        console.print(
            f"  [red]{n_attach_failed:{w}d}[/red] attachments failed "
            f"(see warnings above)"
        )


def _entry_url_inputs(
    entry: Entry, custom_properties: Mapping[str, str | None]
) -> tuple[str, list[str], list[str]]:
    """``(primary url, additional URLs, android packages)`` for a KeePass entry.

    Mirrors the extraction in :meth:`Converter._add_bw_entry_to_entries_dict`
    (suffix-ordered for determinism) so callers that need an entry's would-be
    ``login.uris`` -- the report and REF merging -- fold the same inputs the
    migration does.
    """
    url_attrs: list[tuple[int, str]] = []
    app_attrs: list[tuple[int, str]] = []
    for key, value in custom_properties.items():
        if value and is_url_attribute_key(key):
            bucket = app_attrs if is_android_app_key(key) else url_attrs
            bucket.append((url_attribute_index(key), value))
    return (
        entry.url or "",
        [v for _, v in sorted(url_attrs)],
        [v for _, v in sorted(app_attrs)],
    )


def _open_keepass_database(
    keepass_file_path: str,
    keepass_password: str | None,
    keepass_keyfile_path: str | None,
) -> PyKeePass:
    """Open a KeePass database, raising :class:`ConversionError` on unreadable input."""
    try:
        return PyKeePass(
            filename=keepass_file_path,
            password=keepass_password,
            keyfile=keepass_keyfile_path,
        )
    except CredentialsError:
        raise ConversionError(
            f"Could not open KeePass database {keepass_file_path!r}: "
            "wrong password or key file."
        ) from None
    except (HeaderChecksumError, PayloadChecksumError, OSError) as exc:
        raise ConversionError(
            f"Could not read KeePass database {keepass_file_path!r}: {exc}"
        ) from None


def collect_keepass_uris(
    keepass_file_path: str,
    keepass_password: str | None,
    keepass_keyfile_path: str | None,
    *,
    uri_match: UriMatchValue = None,
    interpret_uri_syntax: bool = True,
) -> list[str]:
    """Return the login-URI values migration would write for every entry.

    Read-only helper for the ``--report-uris keepass`` collision report: each
    entry's primary URL plus its ``KP2A_URL*`` / ``URL_*`` / ``AndroidApp*``
    attributes are run through the same :func:`build_login_uris` the migration
    uses, so the report previews exactly the URIs that would be written --
    including quote/wildcard transforms and dropped non-web schemes -- not the
    raw values.
    """
    kp = _open_keepass_database(
        keepass_file_path, keepass_password, keepass_keyfile_path
    )
    uris: list[str] = []
    for entry in kp.entries:
        custom_properties = _read_entry_custom_properties(entry).values
        primary, additional, android = _entry_url_inputs(entry, custom_properties)
        uris.extend(
            bw_uri["uri"]
            for bw_uri in build_login_uris(
                primary_url=primary,
                additional_urls=additional,
                android_packages=android,
                plain_match=uri_match,
                interpret_syntax=interpret_uri_syntax,
            )
        )
    return uris


class Converter:
    _keepass_file_path: str
    _keepass_password: str | None
    _keepass_keyfile_path: str | None
    _bitwarden_password: str
    _bitwarden_organization_id: str | None
    _bitwarden_coll_id: str | None
    _path2name: bool
    _path2nameskip: int
    _import_tags: list[str] | None
    _skip_expired: bool
    _include_recyclebin: bool
    _migrate_metadata: bool
    _update_existing: bool
    _include_oversize_secrets: bool
    _create_folders: bool
    _uri_match: UriMatchValue
    _interpret_uri_syntax: bool
    _totp_pps: bool
    _kp_ref_entries: list[Entry]
    _entries: dict[str, EntryValue]
    _member_reference_resolving_dict: dict[str, str]
    _ref_entries_by_uuid: dict[str, Entry]
    _resolved_ref_items: dict[str, EntryValue | None]
    _refs_in_progress: set[str]
    _generated_metadata_ids: set[str]
    _legacy_ref_states: dict[str, _LegacyRefState]
    _legacy_ref_order: dict[str, int]
    _legacy_ref_results: dict[str, EntryValue | None]

    def __init__(
        self,
        keepass_file_path: str,
        keepass_password: str | None,
        keepass_keyfile_path: str | None,
        bitwarden_password: str,
        bitwarden_organization_id: str | None,
        bitwarden_coll_id: str | None,
        path2name: bool,
        path2nameskip: int,
        import_tags: list[str] | None,
        *,
        skip_expired: bool = False,
        include_recyclebin: bool = False,
        migrate_metadata: bool = True,
        update_existing: bool = True,
        force_update: bool = False,
        include_oversize_secrets: bool = False,
        create_folders: bool = True,
        uri_match: UriMatchValue = None,
        interpret_uri_syntax: bool = True,
        totp_pps: bool = False,
        map_templates: bool = False,
        template_map: dict[str, TemplateRule] | None = None,
        ssh_rules: tuple[SshRule, ...] = (),
        archive_history: bool = False,
        migrate_password_history: bool = True,
        checkpoint_path: str | None = None,
        entry_id: str | None = None,
        item_id: str | None = None,
    ) -> None:
        """Initialise the converter with KeePass source and Bitwarden target settings."""
        self._selected_entry_id = (
            source_uuid(entry_id) if entry_id is not None else None
        )
        self._selected_item_id = item_id
        self._selection: ItemSelection | None = None
        self._previewing = False
        self._preview_sources: dict[str, dict[str, int]] = {}
        self._preview_groups: list[PreviewGroup] = []
        self._preview_failures: dict[str, list[str]] = {}
        self._attachment_plans: dict[str, AttachmentPlan] = {}
        self._checkpoint_path = checkpoint_path
        self._checkpoint: AttachmentCheckpoint | None = None
        self._checkpoint_entry_ids: dict[str, str] = {}
        self._checkpoint_cleanup: list[tuple[str, str, str]] = []
        self._source_scope_id = ""
        self._keepass_file_path = keepass_file_path
        self._keepass_password = keepass_password
        self._keepass_keyfile_path = keepass_keyfile_path
        self._bitwarden_password = bitwarden_password
        self._bitwarden_organization_id = bitwarden_organization_id
        self._bitwarden_coll_id = bitwarden_coll_id
        self._path2name = path2name
        self._path2nameskip = path2nameskip
        self._import_tags = import_tags
        self._skip_expired = skip_expired
        self._include_recyclebin = include_recyclebin
        self._migrate_metadata = migrate_metadata
        self._update_existing = update_existing
        self._force_update_all = force_update
        self._include_oversize_secrets = include_oversize_secrets
        self._create_folders = create_folders
        self._uri_match = uri_match
        self._interpret_uri_syntax = interpret_uri_syntax
        self._totp_pps = totp_pps
        self._map_templates = map_templates
        self._template_map = template_map or {}
        self._ssh_rules = ssh_rules
        self._ssh_sources: dict[str, tuple[SshRule, dict[str, str | None]]] = {}
        self._entry_templates: dict[str, TemplateRule] = {}

        self._archive_history = archive_history
        self._migrate_password_history = migrate_password_history
        self._kp_ref_entries = []
        self._entries = {}
        self._ref_entries_by_uuid = {}
        self._resolved_ref_items = {}
        self._refs_in_progress = set()
        self._generated_metadata_ids = set()
        self._legacy_ref_states = {}
        self._legacy_ref_order = {}
        self._legacy_ref_results = {}

        self._member_reference_resolving_dict = {"username": "U", "password": "P"}

    @staticmethod
    def _convert_pem_to_base64url(pem_key: str) -> str:
        """Validate a PKCS#8 P-256 private key and encode it for Bitwarden."""
        match = re.fullmatch(
            r"-----BEGIN PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+)\s+-----END PRIVATE KEY-----",
            pem_key.strip(),
        )
        if match is None:
            raise ValueError("Expected a PKCS#8 private key")
        raw_bytes = base64.b64decode("".join(match[1].split()), validate=True)
        key = serialization.load_der_private_key(raw_bytes, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise TypeError("Only ECDSA P-256 passkeys are supported")
        encoded = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        if encoded != raw_bytes:
            raise ValueError("Expected canonical PKCS#8 DER without trailing data")
        return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode()

    @staticmethod
    def _passkey_identifier(value: str, *, user_handle: bool = False) -> None:
        """Reject malformed identifiers without repairing or discarding bytes."""
        if not user_handle:
            try:
                if str(UUID(value)) == value.lower():
                    return
            except ValueError:
                pass
            value = value.removeprefix("b64.")
        if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value) is None:
            raise ValueError("Invalid base64url identifier")
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
        if not decoded or (user_handle and len(decoded) > 64):
            raise ValueError("Invalid identifier length")
        if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value.rstrip("="):
            raise ValueError("Noncanonical base64url identifier")

    def _build_fido2_credentials(
        self,
        entry: Entry,
        custom_properties: Mapping[str, str | None],
    ) -> list[BwFido2Credential] | None:
        """Extract KeePassXC passkey attributes and convert to Bitwarden fido2Credentials format."""
        credential_id = custom_properties.get("KPEX_PASSKEY_CREDENTIAL_ID")
        private_key_pem = custom_properties.get("KPEX_PASSKEY_PRIVATE_KEY_PEM")

        if not any(key.startswith(KPEX_PASSKEY_PREFIX) for key in custom_properties):
            return None

        relying_party = custom_properties.get("KPEX_PASSKEY_RELYING_PARTY")
        user_handle = custom_properties.get("KPEX_PASSKEY_USER_HANDLE")
        try:
            if (
                not credential_id
                or not private_key_pem
                or not relying_party
                or not user_handle
            ):
                raise ValueError("Missing required passkey attribute")
            self._passkey_identifier(credential_id)
            self._passkey_identifier(user_handle, user_handle=True)
            domain = relying_party.encode("idna").decode()
            if len(domain) > 253 or any(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                is None
                for label in domain.split(".")
            ):
                raise ValueError("Invalid relying party ID")
            key_value = self._convert_pem_to_base64url(private_key_pem)
        except ValueError, TypeError, binascii.Error, UnsupportedAlgorithm:
            logger.warning(
                "Passkey conversion failed for entry %s; keeping source attributes "
                "as hidden fields (oversized-secret policy still applies).",
                entry.title,
            )
            return None

        creation_date: str | None = entry.ctime.isoformat() if entry.ctime else None

        cred: BwFido2Credential = {
            "credentialId": mark_credential_id(credential_id),
            "keyType": "public-key",
            "keyAlgorithm": "ECDSA",
            "keyCurve": "P-256",
            "keyValue": key_value,
            "rpId": custom_properties.get("KPEX_PASSKEY_RELYING_PARTY") or "",
            "rpName": custom_properties.get("KPEX_PASSKEY_RELYING_PARTY") or "",
            "userHandle": custom_properties.get("KPEX_PASSKEY_USER_HANDLE") or "",
            "userName": custom_properties.get("KPEX_PASSKEY_USERNAME")
            or entry.username
            or "",
            "userDisplayName": custom_properties.get("KPEX_PASSKEY_USERNAME")
            or entry.username
            or "",
            "counter": "0",
            "discoverable": "true",
            "creationDate": creation_date,
        }
        return [cred]

    def _create_bw_python_object(
        self,
        title: str,
        notes: str,
        url: str,
        totp: str,
        username: str,
        password: str,
        custom_properties: dict[str, FieldSpec],
        fido2_credentials: list[BwFido2Credential] | None = None,
        additional_urls: list[str] | None = None,
        android_packages: list[str] | None = None,
    ) -> BwItemCreate:
        """Build a Bitwarden item dict from individual entry fields.

        The primary ``url`` plus any KeePass(XC) additional URLs and Android
        package ids are folded into ``login.uris`` with per-URI match modes (see
        :mod:`kp2bw.uri_mapping`), rather than left as inert custom fields.
        """
        uris: list[BwUri] = build_login_uris(
            primary_url=url,
            additional_urls=additional_urls or [],
            android_packages=android_packages or [],
            plain_match=self._uri_match,
            interpret_syntax=self._interpret_uri_syntax,
        )
        login: BwItemLogin = BwItemLogin(
            uris=uris,
            username=username,
            password=password,
            totp=totp or None,
            passwordRevisionDate=None,
        )
        if fido2_credentials:
            login["fido2Credentials"] = fido2_credentials

        fields: list[BwField] = [
            BwField(name=key, value=value, type=ftype)
            for key, (value, ftype) in custom_properties.items()
            if value is not None
        ]

        return BwItemCreate(
            organizationId=self._bitwarden_organization_id,
            collectionIds=[],
            folderId=None,
            type=BW_ITEM_TYPE_LOGIN,
            name=title,
            notes=notes,
            favorite=False,
            fields=fields,
            login=login,
            secureNote=None,
            card=None,
            identity=None,
        )

    def _generate_folder_name(self, entry: Entry) -> str | None:
        """Return the full group path as a ``/``-joined folder name."""
        group = entry.group
        if group is None or not group.path:
            return None
        return "/".join(p for p in group.path if p is not None)

    def _generate_prefix(self, entry: Entry, skip: int) -> str:
        """Build a display prefix from the group path, skipping the first *skip* segments."""
        group = entry.group
        if group is None or not group.path:
            return ""
        out = ""
        for item in islice(group.path, skip, None):
            if item is not None:
                out += item + " / "
        return out

    def _get_folder_firstlevel(self, entry: Entry) -> str | None:
        """Return the first path segment of the entry's group (top-level folder)."""
        group = entry.group
        if group is None or not group.path:
            return None
        return group.path[0]

    def _is_in_recyclebin(self, entry: Entry, recyclebin_group: Group | None) -> bool:
        """Check if an entry is inside the recycle bin group."""
        if recyclebin_group is None:
            return False
        group: Group | None = entry.group
        while group is not None:
            if group == recyclebin_group:
                return True
            group = group.parentgroup
        return False

    def _build_metadata_field(self, entry: Entry) -> FieldSpec | None:
        """Build deterministic JSON containing KeePass tags and expiry.

        Existing YAML fields keep their original sync signatures and are
        upgraded through normal reconciliation, after manual-edit checks.
        """
        meta: dict[str, object] = {}
        if entry.expires and entry.expiry_time:
            meta["expires"] = entry.expiry_time.isoformat()
        if entry.tags:
            meta["tags"] = list(entry.tags)
        if not meta:
            return None
        text = json.dumps(meta, ensure_ascii=True, sort_keys=True)
        return (text, 0)

    def _add_bw_entry_to_entries_dict(self, entry: Entry) -> None:
        """Use execution conversion, retaining per-entry blockers during preview."""
        try:
            self._build_bw_entry(entry)
        except ConversionError as exc:
            if not self._previewing:
                raise
            self._preview_failures.setdefault(entry.uuid.hex.upper(), []).append(
                str(exc)
                if isinstance(exc, FieldLimitError)
                else "Source conversion failed; check this entry's references, history and mapping configuration"
            )

    def _build_bw_entry(self, entry: Entry) -> None:
        """Convert a KeePass entry into a Bitwarden item and store it in ``_entries``."""
        folder = self._generate_folder_name(entry)
        prefix = ""
        if folder and self._path2name:
            prefix = self._generate_prefix(entry, self._path2nameskip)

        custom_property_data = _read_entry_custom_properties(entry)
        custom_props = custom_property_data.values
        custom_protected = custom_property_data.protected_keys
        fido2_credentials = self._build_fido2_credentials(entry, custom_props)

        # Resolve TOTP/HOTP from entry.otp or the KeePass TimeOtp-*/HmacOtp-*
        # custom fields.  This decides which fields are folded into login.totp
        # (and must be dropped here) and which secrets must remain hidden.
        otp_result = resolve_otp(
            entry.otp,
            custom_props,
            entry_label=entry.title or "_untitled",
            totp_pps=self._totp_pps,
        )
        for warning in otp_result.warnings:
            logger.warning(f"{entry.title or '_untitled'}: {warning}")

        custom_properties: dict[str, FieldSpec] = {}
        generated_attachments: list[AttachmentItem] = []
        # KeePass(XC) additional URLs / Android packages are folded into
        # login.uris (not custom fields); collected here keyed by their suffix so
        # the emitted URI order is deterministic across re-runs.
        url_attrs: list[tuple[int, str]] = []
        app_attrs: list[tuple[int, str]] = []
        for key, value in custom_props.items():
            # Skip passkey attributes and OTP fields folded into login.totp.
            if (
                fido2_credentials and key.startswith(KPEX_PASSKEY_PREFIX)
            ) or key in otp_result.consumed_keys:
                continue
            # Route URL/app attributes to login.uris instead of custom fields.
            if is_url_attribute_key(key):
                if value:
                    bucket = app_attrs if is_android_app_key(key) else url_attrs
                    bucket.append((url_attribute_index(key), value))
                continue
            # A value over the item-size limit is offloaded to a <key>.txt
            # attachment below (mirroring the notes handling); keep it out of the
            # inline fields entirely so it is not also stored inline, which would
            # duplicate it and can hit Bitwarden's field-size limit.
            require_field(key, NAME_LIMIT, "Custom field name")
            if not fits_field(value, FIELD_VALUE_LIMIT):
                continue
            if (
                key.startswith(KPEX_PASSKEY_PREFIX)
                or key in otp_result.hidden_keys
                or key in custom_protected
            ):
                custom_properties[key] = (value, 1)
            else:
                custom_properties[key] = (value, 0)

        entry_uuid = str(entry.uuid).replace("-", "").upper()
        # Fold KeePass metadata (tags, expiry) into one KP2BW_META JSON field
        # when enabled; omitted on entries with neither, so most items stay clean.
        if self._migrate_metadata:
            meta_field = self._build_metadata_field(entry)
            if meta_field is not None:
                if fits_field(meta_field[0], FIELD_VALUE_LIMIT):
                    custom_properties[KP2BW_META_FIELD_NAME] = meta_field
                    self._generated_metadata_ids.add(entry_uuid)
                elif meta_field[0] is not None:
                    generated_attachments.append((KP2BW_META_FIELD_NAME, meta_field[0]))

        # Stamp the stable identity marker — always, independent of --metadata.
        # A plain-text field carrying the source KeePass entry UUID so dedup keys
        # on it instead of the mutable (folder, title); see bw_serve.item_kp2bw_id
        # / _build_dedup_index. Excluded from the content diff (_fields_signature)
        # so it never makes a re-run look "changed". Text, not hidden: it is an
        # identifier, not a secret.
        custom_properties[KP2BW_ID_FIELD_NAME] = (entry_uuid, 0)

        # Build FIDO2/passkey credentials from KeePassXC attributes
        if fido2_credentials:
            logger.log(VERBOSE, f"  Migrating passkey for entry: {entry.title}")

        # Budget the complete notes, including the generated expiry marker.
        expired_prefix = "[EXPIRED] " if entry.expired else ""
        notes = expired_prefix + (entry.notes or "")
        if not fits_field(notes, NOTES_LIMIT):
            generated_attachments.append(
                source_file("notes", "", 1, "notes.txt", (entry.notes or "").encode())
            )
            notes = expired_prefix

        title: str = prefix + entry.title if entry.title else prefix + "_untitled"
        firstlevel = self._get_folder_firstlevel(entry)

        bw_item_object = self._create_bw_python_object(
            title=title,
            notes=notes,
            url=entry.url or "",
            totp=otp_result.totp or "",
            username=entry.username or "",
            password=entry.password or "",
            custom_properties=custom_properties,
            fido2_credentials=fido2_credentials,
            additional_urls=[v for _, v in sorted(url_attrs)],
            android_packages=[v for _, v in sorted(app_attrs)],
        )

        # Stamp the content signature kp2bw is writing, so a later re-run can tell
        # a user's manual Bitwarden edit (signature no longer matches) from kp2bw's
        # own prior write (this restamps it). Plain text, not hidden: like
        # KP2BW_ID it is metadata, not a secret, and a hidden field is only
        # UI-masked, not protected. Excluded from the content signature itself, so
        # it never makes a re-run look "changed".
        previous_passwords = (
            native_password_history(entry) if self._migrate_password_history else []
        )
        if previous_passwords:
            apply_native_history(bw_item_object, previous_passwords)
            logger.log(
                VERBOSE,
                "Prepared %d previous passwords for entry %s",
                len(previous_passwords),
                entry_uuid,
            )
        self._stamp_content(bw_item_object)

        # get attachments to store later on. A value over the inline size limit
        # is offloaded to a <key>.txt attachment, with three exceptions:
        #   * consumed OTP keys are already folded into login.totp, so dropping
        #     the raw field is deduplication, not loss -- skip it silently.
        #   * a passkey attribute, hidden OTP secret, or KeePass-protected field
        #     survives nowhere else and is a secret, so dropping it IS data loss.
        #     By default it is not written to a plaintext attachment (a secret in
        #     a readable .txt file); we warn instead of dropping it silently.
        #     Opting in via ``--include-oversize-secrets`` offloads it too.
        # The value itself is never logged in either branch.
        label = entry.title or "_untitled"
        attachments: list[AttachmentItem] = generated_attachments
        if self._archive_history:
            archive = history_archive(entry, entry._kp.binaries if entry._kp else [])
            if archive is not None:
                attachments.append(
                    source_file("history", "", 1, "history.json", archive.data)
                )
                logger.log(
                    VERBOSE,
                    "Prepared %d historical records for archival on entry %s",
                    archive.records,
                    entry_uuid,
                )
                if archive.missing_binaries:
                    if self._previewing:
                        self._preview_failures.setdefault(entry_uuid, []).append(
                            "Historical attachment bodies are missing; restore them in KeePass to produce a complete archive"
                        )
                    logger.warning(
                        "Entry %s: %d historical attachment bodies are unavailable; their references remain in the archive",
                        entry_uuid,
                        archive.missing_binaries,
                    )
        for key, value in custom_props.items():
            if value is None or fits_field(value, FIELD_VALUE_LIMIT):
                continue
            if (
                key in otp_result.consumed_keys
                or is_url_attribute_key(key)
                or (fido2_credentials and key.startswith(KPEX_PASSKEY_PREFIX))
            ):
                continue
            if (
                key.startswith(KPEX_PASSKEY_PREFIX)
                or key in otp_result.hidden_keys
                or key in custom_protected
            ):
                if self._include_oversize_secrets:
                    logger.warning(
                        f"{label}: secret field '{key}' exceeds the "
                        f"{FIELD_VALUE_LIMIT}-character encrypted field limit; offloading "
                        f"it to the attachment '{key}.txt' "
                        "(--include-oversize-secrets)."
                    )
                    attachments.append((key, value))
                else:
                    if self._previewing:
                        self._preview_failures.setdefault(entry_uuid, []).append(
                            "An oversized secret field would be omitted; shorten it or use --include-oversize-secrets to preserve it as an attachment"
                        )
                    logger.warning(
                        f"{label}: secret field '{key}' exceeds the "
                        f"{FIELD_VALUE_LIMIT}-character encrypted field limit and was not "
                        "migrated; re-run with --include-oversize-secrets to "
                        "offload it to an attachment."
                    )
                continue
            attachments.append((key, value))

        # Same value stamped as KP2BW_ID above; it is this entry's dedup key.
        entry_key: str = entry_uuid
        if entry.attachments:
            attachments += entry.attachments

        validate_item(bw_item_object)
        self._entries[entry_key] = (
            folder,
            firstlevel,
            bw_item_object,
            list(self._attachment_sources(attachments)),
        )

    def _parse_kp_ref_string(self, ref_string: str) -> tuple[str, str, str]:
        """Parse a ``{REF:...}`` string into ``(field, lookup_mode, uuid)``."""
        # {REF:U@I:CFC0141068E83547BCEEAF0C1ADABAE0}
        tokens = ref_string.split(":")

        if len(tokens) != 3:
            raise ConversionError("Invalid REF string found")

        ref_compare_string = tokens[2][:-1]
        try:
            field_referenced, lookup_mode = tokens[1].split("@")
        except ValueError as exc:
            # Malformed token, e.g. "{REF:UI:...}" with no '@' separator. Surface
            # it the same way as the length check so the entry-level handler warns
            # and skips just this entry instead of aborting the whole run.
            raise ConversionError("Invalid REF string found") from exc

        return (field_referenced, lookup_mode, ref_compare_string)

    def _get_referenced_entry(
        self, lookup_mode: str, ref_compare_string: str
    ) -> EntryValue:
        """Look up a referenced entry by UUID, resolving REF chains on demand.

        A reference may point at a normal entry (already in ``_entries``) or at
        another REF entry that has not been resolved yet -- a chain such as
        ``A -> B -> C``. In the latter case the target REF entry is resolved
        first so the chain collapses onto whatever it ultimately maps to,
        instead of raising a ``KeyError`` and dropping the rest of the chain.
        """
        if lookup_mode != "I":
            raise ConversionError("Unsupported REF lookup_mode")

        # KP_ID lookup: fast path for an already-parsed normal entry.
        key = ref_compare_string.upper()
        entry = self._entries.get(key)
        if entry is not None:
            return entry

        # Target is itself a pending REF entry; resolve it (recursively) so the
        # chain maps onto its eventual item rather than failing here.
        ref_kp_entry = self._ref_entries_by_uuid.get(key)
        if ref_kp_entry is not None:
            resolved = self._resolve_single_ref_entry(ref_kp_entry)
            if resolved is not None:
                return resolved

        logger.warning(f"!! - Could not resolve REF to {ref_compare_string} !!")
        raise KeyError(key)

    def _find_referenced_value(
        self, ref_entry: BwItemCreate, field_referenced: str
    ) -> str | None:
        """Extract the referenced login field (username/password) from a resolved entry."""
        login = ref_entry["login"]
        # Build an explicit member→value mapping so we can look up by member name
        # without a dynamic TypedDict key access (which type checkers can't verify).
        field_values: dict[str, str | None] = {
            "username": login["username"],
            "password": login["password"],
        }
        for member, reference_key in self._member_reference_resolving_dict.items():
            if field_referenced == reference_key:
                return field_values.get(member)

        raise ConversionError("Unsupported REF field_referenced")

    def _load_keepass_data(self) -> None:
        """Open the KeePass database and populate ``_entries`` with parsed items."""
        # aggregate entries
        kp = _open_keepass_database(
            self._keepass_file_path,
            self._keepass_password,
            self._keepass_keyfile_path,
        )
        if self._checkpoint_path:
            self._source_scope_id = metadata_digest({
                "path": str(Path(self._keepass_file_path).resolve()),
                "root": kp.root_group.uuid.hex,
            })

        # reset data structures
        self._kp_ref_entries = []
        self._entries = {}
        self._generated_metadata_ids = set()
        self._legacy_ref_states = {}
        self._legacy_ref_order = {}
        self._legacy_ref_results = {}

        # Identify recycle bin group for filtering
        recyclebin_group: Group | None = kp.recyclebin_group

        entries: list[Entry] = kp.entries or []
        self._resolved_ref_items = {}
        if self._previewing:
            self._preview_groups = group_inventory(kp.groups)
            self._preview_sources = {
                entry.uuid.hex.upper(): source_inventory(entry) for entry in entries
            }
            seen: set[str] = set()
            for entry in entries:
                identifier = entry.uuid.hex.upper()
                if identifier in seen:
                    self._preview_failures.setdefault(identifier, []).append(
                        "Multiple KeePass entries share this UUID; assign distinct source identities before migration"
                    )
                seen.add(identifier)
        self._entry_templates = {}
        self._ssh_sources = {}
        templates_present = {
            source.uuid.hex.upper()
            for source in entries
            if _read_entry_custom_properties(source).values.get("_etm_template") == "1"
        }
        for source in entries if self._ssh_rules else []:
            props = _read_entry_custom_properties(source).values
            if props.get("_etm_template") == "1":
                continue
            fields = {
                "Title": source.title,
                "UserName": source.username,
                "Password": source.password,
                "URL": source.url,
                "Notes": source.notes,
                **props,
            }
            template = template_uuid(props.get("_etm_template_uuid") or "")
            if template not in templates_present:
                template = None
            matching_rules = [
                rule
                for rule in self._ssh_rules
                if rule.matches(
                    self._generate_folder_name(source) or "", template, fields
                )
            ]
            if len(matching_rules) > 1:
                raise ConversionError(
                    "An entry matches multiple SSH mapping rules; make the selectors unambiguous"
                )
            if matching_rules:
                self._ssh_sources[source.uuid.hex.upper()] = (matching_rules[0], fields)
        if self._map_templates:
            templates: dict[str, TemplateRule] = {}
            for source in entries:
                props = _read_entry_custom_properties(source).values
                if props.get("_etm_template") != "1":
                    continue
                identifier = source.uuid.hex.upper()
                kind = recognize_template(identifier, source.title or "")
                rule = self._template_map.get(identifier)
                if rule is None and kind:
                    rule = TemplateRule(kind, {})
                if rule:
                    templates[identifier] = rule
            for source in entries:
                props = _read_entry_custom_properties(source).values
                identifier = template_uuid(props.get("_etm_template_uuid") or "")
                if identifier and identifier in templates:
                    self._entry_templates[source.uuid.hex.upper()] = templates[
                        identifier
                    ]

        if self._selection is not None:
            matches = [
                e for e in entries if e.uuid.hex.upper() == self._selection.source_id
            ]
            if len(matches) != 1:
                raise ConversionError("Selected KeePass entry is missing or ambiguous")
            selected = matches[0]
            if (
                (
                    not self._include_recyclebin
                    and self._is_in_recyclebin(selected, recyclebin_group)
                )
                or (self._skip_expired and selected.expired)
                or (
                    self._import_tags
                    and not set(self._import_tags).intersection(selected.tags)
                )
            ):
                raise ConversionError(
                    "Selected KeePass entry is excluded by import filters"
                )
            # Reconstruct the selected item's full REF component, including
            # aliases contributing URLs/TOTP to it. Only the selected result is
            # written; unrelated entries are never parsed or migrated.
            by_uuid: dict[str, list[Entry]] = {}
            references: dict[str, list[str]] = {}
            inbound: dict[str, set[str]] = {}
            invalid_refs: set[str] = set()
            for candidate in entries:
                key = candidate.uuid.hex.upper()
                by_uuid.setdefault(key, []).append(candidate)
                targets: list[str] = []
                try:
                    for member in self._member_reference_resolving_dict:
                        value = getattr(candidate, member)
                        if value and KP_REF_IDENTIFIER in value:
                            _, lookup, target = self._parse_kp_ref_string(value)
                            if lookup != "I":
                                raise ConversionError(
                                    "Unsupported selected-entry REF lookup"
                                )
                            targets.append(source_uuid(target))
                except ConversionError:
                    invalid_refs.add(key)
                references[key] = targets
                if (
                    (
                        not self._include_recyclebin
                        and self._is_in_recyclebin(candidate, recyclebin_group)
                    )
                    or (self._skip_expired and candidate.expired)
                    or (
                        self._import_tags
                        and not set(self._import_tags).intersection(candidate.tags)
                    )
                ):
                    continue
                for target in targets:
                    inbound.setdefault(target, set()).add(key)
            needed: set[str] = set()
            pending = [self._selection.source_id]
            while pending:
                key = pending.pop()
                if key in needed:
                    continue
                if len(by_uuid.get(key, [])) != 1:
                    raise ConversionError(
                        "Selected entry has a missing or ambiguous REF dependency"
                    )
                if key in invalid_refs:
                    raise ConversionError(
                        "Selected entry has an invalid REF dependency"
                    )
                needed.add(key)
                pending.extend(references.get(key, []))
                pending.extend(inbound.get(key, set()))
            entries = [e for e in entries if e.uuid.hex.upper() in needed]
        total_entries: int = len(entries)
        skipped_recyclebin = 0
        skipped_expired = 0

        logger.info(f"Found {total_entries} entries in KeePass DB. Parsing now...")
        for entry in entries:
            if (
                self._map_templates or self._ssh_rules
            ) and _read_entry_custom_properties(entry).values.get(
                "_etm_template"
            ) == "1":
                continue
            # Skip recycle bin entries unless explicitly included
            if (
                self._selection is None
                and not self._include_recyclebin
                and self._is_in_recyclebin(entry, recyclebin_group)
            ):
                skipped_recyclebin += 1
                continue

            # Skip expired entries if requested
            if self._selection is None and self._skip_expired and entry.expired:
                skipped_expired += 1
                logger.log(VERBOSE, f"Skipping expired entry: {entry.title}")
                continue

            # prevent not iterable errors at "in" checks
            username: str = entry.username or ""
            password: str = entry.password or ""

            # Skip REFs as ID might not be in dict yet
            if KP_REF_IDENTIFIER in username or KP_REF_IDENTIFIER in password:
                self._kp_ref_entries.append(entry)
                continue

            # Normal entry
            if self._import_tags and self._selection is None:
                for tag in self._import_tags:
                    if tag in entry.tags:
                        self._add_bw_entry_to_entries_dict(entry)
                        break
            else:
                self._add_bw_entry_to_entries_dict(entry)

        if skipped_recyclebin:
            logger.info(f"Skipped {skipped_recyclebin} entries in the Recycle Bin")
        if skipped_expired:
            logger.info(f"Skipped {skipped_expired} expired entries")
        logger.info(f"Parsed {len(self._entries)} entries")

    def _resolve_entries_with_references(self) -> None:
        """Resolve ``{REF:...}`` cross-references and merge or create entries accordingly."""
        ref_entries_length = len(self._kp_ref_entries)

        if ref_entries_length == 0:
            return

        logger.info(f"Resolving {ref_entries_length} REF entries now...")

        # Index pending REF entries by UUID so a reference whose target is itself
        # a REF entry (a chain ``A -> B -> C``) can be resolved on demand rather
        # than failing with a KeyError because the target isn't in ``_entries``.
        self._ref_entries_by_uuid = {
            str(entry.uuid).replace("-", "").upper(): entry
            for entry in self._kp_ref_entries
        }
        self._legacy_ref_order = self._build_legacy_ref_order()
        # Memoise each REF entry's resolved item so it is processed exactly once
        # even when reached early through a chain, and track the in-progress set
        # to break reference cycles.
        self._resolved_ref_items = {}
        self._refs_in_progress = set()
        self._legacy_ref_results = {}

        # Independent sibling aliases can compete to populate one empty TOTP.
        # Resolve them by stable identity so XML ordering cannot pick the winner.
        for kp_entry in sorted(self._kp_ref_entries, key=lambda entry: entry.uuid.hex):
            self._resolve_single_ref_entry(kp_entry)

        logger.log(VERBOSE, f"Resolved {ref_entries_length} REF entries")

    def _build_legacy_ref_order(self) -> dict[str, int]:
        """Return successful REF completion order under the historical traversal."""
        status: dict[str, Literal["visiting", "resolved", "failed"]] = {}
        ordered: list[str] = []

        def visit(entry: Entry) -> bool:
            entry_key = str(entry.uuid).replace("-", "").upper()
            current = status.get(entry_key)
            if current == "resolved":
                return True
            if current in {"visiting", "failed"}:
                return False

            status[entry_key] = "visiting"
            for member in self._member_reference_resolving_dict:
                value = getattr(entry, member)
                if not value or KP_REF_IDENTIFIER not in value:
                    continue
                try:
                    field_referenced, lookup_mode, ref_compare_string = (
                        self._parse_kp_ref_string(value)
                    )
                except ConversionError:
                    status[entry_key] = "failed"
                    return False

                target_key = ref_compare_string.upper()
                target = self._ref_entries_by_uuid.get(target_key)
                if lookup_mode != "I" or (
                    target is None and target_key not in self._entries
                ):
                    status[entry_key] = "failed"
                    return False
                if target is not None and not visit(target):
                    status[entry_key] = "failed"
                    return False
                if (
                    field_referenced
                    not in self._member_reference_resolving_dict.values()
                ):
                    status[entry_key] = "failed"
                    return False

            status[entry_key] = "resolved"
            ordered.append(entry_key)
            return True

        for entry in self._kp_ref_entries:
            visit(entry)
        return {entry_key: index for index, entry_key in enumerate(ordered)}

    def _ref_separate_item_reason(
        self,
        entry: Entry,
        custom_properties: Mapping[str, str | None],
        otp_result: OtpMigration,
    ) -> str | None:
        """Explain why a credential-matching REF alias cannot merge losslessly."""
        unmerged_custom_properties = {
            key
            for key, value in custom_properties.items()
            if value is not None
            and key not in otp_result.consumed_keys
            and not is_url_attribute_key(key)
        }
        if unmerged_custom_properties:
            return "custom fields that cannot be merged"
        if (self._archive_history or self._migrate_password_history) and entry.history:
            return "historical records that cannot be merged"
        if entry.notes or entry.attachments or entry.expired:
            return "notes, attachments, or expiry state that cannot be merged"
        if self._migrate_metadata and (
            entry.tags or (entry.expires and entry.expiry_time is not None)
        ):
            return "metadata that cannot be merged"
        return None

    @staticmethod
    def _item_field_value(item: BwItemCreate | BwItemResponse, name: str) -> str | None:
        """Return the last named field value, preferring kp2bw's appended fields."""
        for field in reversed(item["fields"]):
            if field["name"] == name:
                return field["value"]
        return None

    def _merge_ref_uris(
        self,
        item: BwItemCreate,
        entry: Entry,
        custom_properties: Mapping[str, str | None],
    ) -> None:
        """Merge one REF alias's deduplicated URI inputs into *item*."""
        existing_uris = item["login"]["uris"]
        existing_values = {uri["uri"] for uri in existing_uris}
        primary, additional, android = _entry_url_inputs(entry, custom_properties)
        for bw_uri in build_login_uris(
            primary_url=primary,
            additional_urls=additional,
            android_packages=android,
            plain_match=self._uri_match,
            interpret_syntax=self._interpret_uri_syntax,
        ):
            if bw_uri["uri"] not in existing_values:
                existing_uris.append(bw_uri)
                existing_values.add(bw_uri["uri"])

    def _record_legacy_ref_merge(
        self,
        item: BwItemCreate,
        entry: Entry,
        custom_properties: Mapping[str, str | None],
    ) -> None:
        """Replay old URI-only merging so safe upgrades are recognizable."""
        kp_uuid = self._item_field_value(item, KP2BW_ID_FIELD_NAME)
        sync_stamp = self._item_field_value(item, KP2BW_SYNC_FIELD_NAME)
        entry_key = str(entry.uuid).replace("-", "").upper()
        merge_order = self._legacy_ref_order.get(entry_key)
        if kp_uuid is None or sync_stamp is None or merge_order is None:
            return

        state = self._legacy_ref_states.get(kp_uuid)
        if state is None:
            legacy_item = copy.deepcopy(item)
            # Older releases overwrote reserved source fields and ignored later
            # duplicates. Replay that only for recognizing historical REF output.
            old_fields: list[BwField] = []
            for field in legacy_item["fields"]:
                origin = source_field_origin(field["name"])
                if origin is not None:
                    name, occurrence = origin
                    if occurrence > 1 or name in {
                        KP2BW_ID_FIELD_NAME,
                        KP2BW_SYNC_FIELD_NAME,
                    }:
                        continue
                    if (
                        name == KP2BW_META_FIELD_NAME
                        and kp_uuid in self._generated_metadata_ids
                    ):
                        continue
                    field["name"] = name
                old_fields.append(field)
            legacy_item["fields"] = old_fields
            # Replay the historical YAML metadata too. This shadow is built
            # from our own generated JSON, never from arbitrary vault input.
            if kp_uuid in self._generated_metadata_ids:
                for field in legacy_item["fields"]:
                    if field["name"] == KP2BW_META_FIELD_NAME:
                        field["value"] = yaml.safe_dump(
                            json.loads(field["value"] or "{}"),
                            default_flow_style=False,
                            allow_unicode=False,
                            sort_keys=True,
                        ).rstrip("\n")
            self._stamp_content(legacy_item)
            sync_stamp = content_signature(legacy_item)
            base_uris = copy.deepcopy(legacy_item["login"]["uris"])
            state = _LegacyRefState(sync_stamp, legacy_item, base_uris, {})
            self._legacy_ref_states[kp_uuid] = state

        primary, additional, android = _entry_url_inputs(entry, custom_properties)
        state.uri_merges[merge_order] = build_login_uris(
            primary_url=primary,
            additional_urls=additional,
            android_packages=android,
            plain_match=self._uri_match,
            interpret_syntax=self._interpret_uri_syntax,
        )

        legacy_uris = copy.deepcopy(state.base_uris)
        for order in sorted(state.uri_merges):
            existing_values = {uri["uri"] for uri in legacy_uris}
            legacy_uris.extend(
                copy.deepcopy(uri)
                for uri in state.uri_merges[order]
                if uri["uri"] not in existing_values
            )
        state.item["login"]["uris"] = legacy_uris

    def _resolve_single_ref_entry(self, kp_entry: Entry) -> EntryValue | None:
        """Resolve one REF entry, returning the item references to it should target.

        Returns the merged-into item when *kp_entry*'s resolved credentials match
        its referent, the newly created item when they differ, or ``None`` when
        the entry's references cannot be resolved (missing target or a reference
        cycle). The result is memoised so a chain that resolves this entry early
        does not process it a second time.
        """
        entry_key: str = str(kp_entry.uuid).replace("-", "").upper()

        # Resolve each REF entry once; a chain may have resolved it already.
        if entry_key in self._resolved_ref_items:
            return self._resolved_ref_items[entry_key]
        # Reference cycle (e.g. ``A -> B -> A``): stop so recursion terminates.
        # The originating entry then fails to resolve and is reported below.
        if entry_key in self._refs_in_progress:
            return None

        self._refs_in_progress.add(entry_key)
        try:
            # replace values
            referenced_results: list[EntryValue] = []
            legacy_referenced_results: list[EntryValue] = []
            legacy_username = kp_entry.username
            legacy_password = kp_entry.password
            legacy_resolution_failed = False
            for member in self._member_reference_resolving_dict:
                val = getattr(kp_entry, member)
                if val and KP_REF_IDENTIFIER in val:
                    field_referenced, lookup_mode, ref_compare_string = (
                        self._parse_kp_ref_string(val)
                    )
                    ref_result = self._get_referenced_entry(
                        lookup_mode, ref_compare_string
                    )
                    _, _, ref_entry, _ = self._unpack_entry(ref_result)

                    value = self._find_referenced_value(ref_entry, field_referenced)
                    setattr(kp_entry, member, value)

                    referenced_results.append(ref_result)
                    target_key = ref_compare_string.upper()
                    legacy_result = (
                        self._legacy_ref_results.get(target_key)
                        if target_key in self._ref_entries_by_uuid
                        else ref_result
                    )
                    if legacy_result is None:
                        legacy_resolution_failed = True
                    else:
                        _, _, legacy_ref_item, _ = self._unpack_entry(legacy_result)
                        legacy_value = self._find_referenced_value(
                            legacy_ref_item, field_referenced
                        )
                        if member == "username":
                            legacy_username = legacy_value
                        else:
                            legacy_password = legacy_value
                        legacy_referenced_results.append(legacy_result)

            # A merged alias must have one unambiguous canonical referent. If
            # username and password point at different entries, importing the
            # alias separately avoids attaching its URLs/TOTP to whichever REF
            # happened to be processed last.
            canonical_result: EntryValue | None = None
            if referenced_results:
                candidate = referenced_results[0]
                _, _, candidate_item, _ = self._unpack_entry(candidate)
                if all(
                    self._unpack_entry(result)[2] is candidate_item
                    for result in referenced_results[1:]
                ):
                    canonical_result = candidate
                else:
                    logger.warning(
                        f"{kp_entry.title or '_untitled'}: REF fields resolve to "
                        "different entries; importing as a separate item."
                    )

            kp_username = kp_entry.username or ""
            kp_password = kp_entry.password or ""
            credentials_match = False
            ref_item: BwItemCreate | None = None
            if canonical_result is not None:
                _, _, ref_item, _ = self._unpack_entry(canonical_result)
                credentials_match = (
                    ref_item["login"]["username"] == kp_username
                    and ref_item["login"]["password"] == kp_password
                )

            # The historical path merged into its final referent whenever every
            # resolved item shared the alias credentials. Keep that canonical
            # result separate from current content-aware splitting so a parent
            # REF still replays the destination used by old chain resolution.
            legacy_canonical_result: EntryValue | None = None
            if not legacy_resolution_failed and legacy_referenced_results:
                old_username = legacy_username or ""
                old_password = legacy_password or ""
                old_merge_matches = all(
                    self._unpack_entry(result)[2]["login"]["username"] == old_username
                    and self._unpack_entry(result)[2]["login"]["password"]
                    == old_password
                    for result in legacy_referenced_results
                )
                if old_merge_matches:
                    legacy_canonical_result = legacy_referenced_results[-1]
                    _, _, old_merge_item, _ = self._unpack_entry(
                        legacy_canonical_result
                    )
                    old_custom_properties = _read_entry_custom_properties(kp_entry)
                    self._record_legacy_ref_merge(
                        old_merge_item, kp_entry, old_custom_properties.values
                    )

            if (
                credentials_match
                and (self._selection is None or entry_key != self._selection.source_id)
                and canonical_result is not None
                and ref_item is not None
            ):
                custom_property_data = _read_entry_custom_properties(kp_entry)
                otp_result = resolve_otp(
                    kp_entry.otp,
                    custom_property_data.values,
                    entry_label=kp_entry.title or "_untitled",
                    totp_pps=self._totp_pps,
                )
                separate_reason = self._ref_separate_item_reason(
                    kp_entry, custom_property_data.values, otp_result
                )
                existing_totp = ref_item["login"]["totp"]
                if (
                    separate_reason is None
                    and otp_result.totp is not None
                    and existing_totp
                    and not totp_values_equivalent(existing_totp, otp_result.totp)
                ):
                    separate_reason = "a TOTP that conflicts with its referent"

                if separate_reason is not None:
                    logger.warning(
                        f"{kp_entry.title or '_untitled'}: REF entry carries "
                        f"{separate_reason}; importing as a separate item."
                    )
                    self._add_bw_entry_to_entries_dict(kp_entry)
                    canonical = self._entries.get(entry_key)
                else:
                    for warning in otp_result.warnings:
                        logger.warning(f"{kp_entry.title or '_untitled'}: {warning}")
                    if otp_result.totp is not None and not existing_totp:
                        ref_item["login"]["totp"] = otp_result.totp

                    self._merge_ref_uris(
                        ref_item, kp_entry, custom_property_data.values
                    )

                    # REF merging mutates content after initial item creation;
                    # keep manual-edit protection aligned with the final payload.
                    self._stamp_content(ref_item)
                    canonical = canonical_result
            else:
                # => create new bitwarden item
                self._add_bw_entry_to_entries_dict(kp_entry)
                canonical = self._entries.get(entry_key)

            self._resolved_ref_items[entry_key] = canonical
            self._legacy_ref_results[entry_key] = (
                None
                if legacy_resolution_failed
                else legacy_canonical_result or canonical
            )
            return canonical

        except FieldLimitError:
            # Invalid destination payloads must abort preflight, including REF chains.
            raise
        except ConversionError, KeyError, AttributeError:
            group = kp_entry.group
            group_path = group.path if group is not None else []
            logger.warning(
                f"!! Could not resolve entry for {group_path}{kp_entry.title} [{kp_entry.uuid!s}] !!"
            )
            self._resolved_ref_items[entry_key] = None
            self._legacy_ref_results[entry_key] = None
            return None
        finally:
            self._refs_in_progress.discard(entry_key)

    @staticmethod
    def _unpack_entry(
        entry_value: EntryValue,
    ) -> tuple[str | None, str | None, BwItemCreate, list[AttachmentItem]]:
        """Destructure an entry value into (folder, firstlevel, item, attachments)."""
        folder, firstlevel, bw_item, attachments = entry_value
        return folder, firstlevel, bw_item, attachments

    def _resolve_collection(
        self,
        bw: BitwardenServeClient,
        bw_item: BwItemCreate,
        folder: str | None,
        firstlevel: str | None,
    ) -> str | None:
        """Resolve and set collection ID on *bw_item*."""
        collection_id: str | None = None
        if self._bitwarden_coll_id in COLLECTION_FOLDER_MODES:
            collection_name = (
                folder
                if self._bitwarden_coll_id == NESTED_COLLECTION_MODE
                else firstlevel
            )
            if collection_name:
                logger.log(VERBOSE, f"Searching Collection {collection_name}")
                collection_id = bw.create_org_collection(collection_name)
        elif self._bitwarden_coll_id:
            collection_id = self._bitwarden_coll_id

        if collection_id is not None:
            # Intentional in-place mutation: _entries is reset by
            # _load_keepass_data() before each convert() run, so mutating
            # bw_item here is safe for the current single-pass architecture.
            bw_item["collectionIds"] = [collection_id]
        return collection_id

    def _resolve_collection_safely(
        self,
        bw: BitwardenServeClient,
        bw_item: BwItemCreate,
        folder: str | None,
        firstlevel: str | None,
    ) -> bool:
        """Resolve+set the collection for *bw_item*, reporting failure non-fatally.

        Returns ``True`` on success.  A :class:`BitwardenClientError` (e.g. the
        org-collection POST is dropped or times out) is logged and reported as
        ``False`` so the caller skips just this entry instead of aborting the
        whole migration -- the same per-entry robustness the create and update
        phases have (issue #24).
        """
        try:
            self._resolve_collection(bw, bw_item, folder, firstlevel)
        except BitwardenClientError as exc:
            logger.warning(
                f"Could not resolve the collection for {bw_item.get('name', '?')!r}; "
                f"skipping it this run (a re-run is safe): {exc}"
            )
            return False
        return True

    @staticmethod
    def _sync_safely(bw: BitwardenServeClient) -> None:
        """Run the pre-attachment sync, reporting failure non-fatally.

        Freshly created item IDs can be momentarily unresolvable by ``bw serve``'s
        attachment endpoint until a sync makes them visible.  A dropped sync is
        non-fatal: the items are already created and :meth:`upload_attachment`
        self-heals with its own sync-and-retry, so a failed pre-emptive sync must
        not abort a run whose items already landed.
        """
        try:
            bw.sync()
        except BitwardenClientError as exc:
            logger.warning(
                f"Pre-attachment sync failed; continuing (uploads self-heal with "
                f"their own sync-and-retry): {exc}"
            )

    @staticmethod
    def _attachment_sources(attachments: list[AttachmentItem]) -> list[SourceFile]:
        sources: list[SourceFile] = []
        occurrences: dict[tuple[str, str], int] = {}
        for attachment in attachments:
            if isinstance(attachment, SourceFile):
                sources.append(attachment)
                continue
            if isinstance(attachment, Attachment):
                kind, key = "original", attachment.filename or "attachment"
            else:
                kind, key = "field", attachment[0]
            occurrence_key = kind, key
            ordinal = occurrences.get(occurrence_key, 0) + 1
            occurrences[occurrence_key] = ordinal
            filename, data = Converter._materialise_attachment(attachment)
            sources.append(source_file(kind, key, ordinal, filename, data))
        sources.sort(key=lambda source: source.kind != "original")
        return plan_attachments(sources, {}, [], lambda _: b"").sources

    @staticmethod
    def _attachment_filename(att: AttachmentItem) -> str:
        """Return the Bitwarden filename an AttachmentItem materialises to.

        Single source of truth for the naming rule, shared by
        :meth:`_materialise_attachment` (which uploads) and upload-if-missing
        reconciliation (which compares names without encoding the payload), so
        the two can never drift apart.
        """
        if isinstance(att, SourceFile):
            return att.filename
        if not isinstance(att, Attachment):
            # Long custom property — (key, value) text tuple
            return att[0] + ".txt"
        # Real pykeepass Attachment
        return att.filename or "attachment"

    @staticmethod
    def _materialise_attachment(att: AttachmentItem) -> tuple[str, bytes]:
        """Convert an AttachmentItem to a ``(filename, data)`` pair."""
        name = Converter._attachment_filename(att)
        if isinstance(att, SourceFile):
            return name, att.data
        if isinstance(att, Attachment):
            return name, att.data
        return name, att[1].encode("UTF-8")

    @staticmethod
    def _fields_signature(
        fields: list[BwField] | None,
    ) -> list[tuple[str, str, int, int | None]]:
        """Order-independent (name, value, type) signature of custom fields.

        The kp2bw-managed stamps (``KP2BW_ID`` identity, ``KP2BW_SYNC`` sync
        signature) are excluded: they are metadata, not user content, so they
        must never make a re-run look "changed" (and on a legacy item they are
        absent, while the desired item always carries ``KP2BW_ID``).
        """
        return fields_signature(fields)

    @staticmethod
    def _login_signature(
        login: BwItemLogin | None,
    ) -> tuple[str, str, str, list[tuple[str, int | None]]]:
        """Signature of the login fields kp2bw owns (creds, totp, URIs)."""
        return login_signature(login)

    @staticmethod
    def _strict_login_signature(
        login: BwItemLogin | None,
    ) -> tuple[
        str,
        str,
        str,
        list[tuple[str, Literal[0, 1, 2, 3, 4, 5] | None]],
        str,
    ]:
        """Login signature used only to recognize exact historical REF output."""
        if login is None:
            return ("", "", "", [], "")
        return (
            login.get("username") or "",
            login.get("password") or "",
            login.get("totp") or "",
            [
                (uri.get("uri", ""), uri.get("match"))
                for uri in (login.get("uris") or [])
            ],
            repr([
                tuple(
                    sorted(
                        (
                            (
                                key,
                                mark_credential_id(value)
                                if key == "credentialId" and isinstance(value, str)
                                else value,
                            )
                            for key, value in credential.items()
                        ),
                        key=lambda item: item[0],
                    )
                )
                for credential in (login.get("fido2Credentials") or [])
            ]),
        )

    @classmethod
    def _login_differs(cls, existing: BwItemLogin | None, desired: BwItemLogin) -> bool:
        """Compare the login fields kp2bw owns (creds, totp, URIs)."""
        return cls._login_signature(existing) != cls._login_signature(desired)

    @staticmethod
    def _content_signature(item: BwItemResponse | BwItemCreate) -> str:
        """Hex digest over exactly the content kp2bw manages on an item.

        Covers name, notes, the custom-field signature (managed stamps excluded)
        and the login signature -- the same surface :meth:`_content_differs`
        compares, so the value stamped into ``KP2BW_SYNC`` on a write and the
        value recomputed on the next run agree whenever a user has not touched
        the item.  A user edit to any of these flips the digest; a kp2bw write
        restamps it.  The digest leaks nothing: every input is already present in
        cleartext on the same item to anyone who can read it.
        """
        return content_signature(item)

    @staticmethod
    def _stamp_content(item: BwItemCreate | BwItemResponse) -> None:
        """Set the managed sync field to the signature of *item*'s current content."""
        stamp_content(item)

    @classmethod
    def _content_differs(
        cls, existing: BwItemResponse, desired: BwItemCreate | BwItemResponse
    ) -> bool:
        """True if the KeePass-derived content diverges from the vault item.

        Compares only the fields kp2bw manages (name, notes, custom fields and
        the login credentials/URIs) so an unchanged re-run stays idempotent and
        never issues a redundant PUT.
        """
        return cls._content_signature(existing) != cls._content_signature(desired)

    @classmethod
    def _is_user_modified(cls, existing: BwItemResponse) -> bool:
        """True if a user edited *existing*'s managed content since kp2bw's write.

        Compares the item's current content signature against the ``KP2BW_SYNC``
        stamp kp2bw wrote last time.  A mismatch means the managed content
        changed outside kp2bw (kp2bw restamps on every write, so its own updates
        never trip this). Pre-3.8.1 stamps remain valid over their original
        coverage and are upgraded on the next safe write. An unstamped item --
        legacy, or not yet written since the feature shipped -- returns ``False``
        so the next run establishes the stamp rather than freezing it behind
        ``--force-update``.
        """
        stamp = item_kp2bw_sync(existing)
        if stamp is None:
            return False
        return not sync_stamp_matches(existing, stamp)

    def _legacy_ref_status(
        self, existing: BwItemResponse, kp_uuid: str
    ) -> Literal["unrelated", "exact", "diverged"]:
        """Classify an item carrying a known pre-fix REF sync stamp."""
        state = self._legacy_ref_states.get(kp_uuid)
        if state is None or item_kp2bw_sync(existing) != state.initial_sync_stamp:
            return "unrelated"
        if self._strict_ref_signature(existing) == self._strict_ref_signature(
            state.item
        ):
            return "exact"
        return "diverged"

    @classmethod
    def _strict_ref_signature(cls, item: BwItemResponse | BwItemCreate) -> str:
        """Digest all content a legacy-upgrade PUT could overwrite."""
        blob = repr((
            item.get("name") or "",
            item.get("notes") or "",
            cls._fields_signature(item.get("fields")),
            cls._strict_login_signature(item.get("login")),
        ))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @staticmethod
    def _build_update_payload(
        existing: BwItemResponse, desired: BwItemCreate
    ) -> BwItemResponse:
        """Build a PUT body that syncs KeePass content onto an existing item.

        Starts from the existing item so server-managed and user-managed fields
        (``id``, ``favorite``, ``folderId``, ``organizationId``, collection
        membership) are preserved, then overwrites the fields kp2bw owns.
        Collection IDs are only ever added to, never dropped: any target IDs are
        appended to the existing ones, and the Bitwarden CLI additionally unions
        the request against the item's real membership server-side, so a content
        PUT cannot remove an item from a collection even though listed items
        report ``collectionIds=null``.  Existing passkeys are preserved when the
        KeePass entry has none, so a re-run can't silently drop a Bitwarden-side
        FIDO2 credential.
        """
        if desired["type"] != 1 and (existing.get("login") or {}).get(
            "fido2Credentials"
        ):
            raise BitwardenClientError(
                "Cannot change item type while it contains a Bitwarden passkey"
            )
        payload: BwItemResponse = copy.copy(existing)
        payload["sshKey"] = copy.deepcopy(desired.get("sshKey"))
        payload["type"] = desired["type"]
        payload["card"] = copy.deepcopy(desired["card"])
        payload["identity"] = copy.deepcopy(desired["identity"])
        payload["secureNote"] = copy.deepcopy(desired["secureNote"])
        payload["name"] = desired["name"]
        payload["notes"] = desired["notes"]
        payload["fields"] = [
            *[copy.copy(field) for field in desired["fields"]],
            *[
                copy.copy(field)
                for field in existing["fields"]
                if is_record_field(field)
            ],
        ]

        desired_login: BwItemLogin = copy.copy(desired["login"])
        ex_login = existing.get("login")
        if (
            desired["type"] == 1
            and "fido2Credentials" not in desired_login
            and ex_login
        ):
            ex_fido2 = ex_login.get("fido2Credentials")
            if ex_fido2:
                kept: list[BwFido2Credential] = []
                for credential in ex_fido2:
                    kept_credential = copy.copy(credential)
                    kept_credential["credentialId"] = mark_credential_id(
                        credential["credentialId"]
                    )
                    kept.append(kept_credential)
                desired_login["fido2Credentials"] = kept
        payload["login"] = desired_login

        if has_managed_history(desired):
            apply_native_history(
                payload, desired.get("passwordHistory") or [], existing=existing
            )
        elif has_managed_history(existing):
            payload["fields"].extend(
                copy.copy(field)
                for field in existing["fields"]
                if field.get("name") == HISTORY_FIELD_NAME
            )

        target_colls = desired.get("collectionIds") or []
        existing_colls = existing.get("collectionIds") or []
        missing = [c for c in target_colls if c not in existing_colls]
        payload["collectionIds"] = existing_colls + missing
        stamp_content(payload)
        return payload

    def _retry_item(
        self, source_id: str, item_id: str, *, force: bool = False, legacy: bool = False
    ) -> str:
        """Return a shell-quoted retry without copying credentials into logs."""
        args = ["kp2bw", self._keepass_file_path]
        if not legacy:
            args.extend(["--entry-id", source_id, "--item-id", item_id])
        if self._bitwarden_organization_id:
            args.extend(["--bitwarden-org", self._bitwarden_organization_id])
        if self._bitwarden_coll_id:
            args.extend(["--bitwarden-collection", self._bitwarden_coll_id])
        args.extend(["--path-to-name-skip", str(self._path2nameskip)])
        for flag, enabled in (
            ("path-to-name", self._path2name),
            ("metadata", self._migrate_metadata),
            ("folder", self._create_folders),
            ("skip-expired", self._skip_expired),
            ("include-recycle-bin", self._include_recyclebin),
            ("interpret-uri-syntax", self._interpret_uri_syntax),
            ("totp-pps", self._totp_pps),
        ):
            args.append(f"--{'' if enabled else 'no-'}{flag}")
        if self._include_oversize_secrets:
            args.append("--include-oversize-secrets")
        if self._import_tags:
            args.extend(["--import-tags", *self._import_tags])
        args.extend([
            "--uri-match",
            next(
                name
                for name in match_value_names()
                if parse_match_name(name) == self._uri_match
            ),
        ])
        if self._keepass_keyfile_path:
            args.extend(["--keepass-keyfile", self._keepass_keyfile_path])
        args.append("--update")
        if force:
            args.append("--force-update")
        if os.name == "nt":
            return "& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in args)
        return shlex.join(args)

    def _reconcile_existing_item(
        self,
        bw: BitwardenServeClient,
        existing: BwItemResponse,
        folder: str | None,
        bw_item: BwItemCreate,
        attachments: list[AttachmentItem],
        *,
        fixed_coll_id: str | None,
        kp_uuid: str,
        force_update: bool = False,
    ) -> tuple[
        Literal["updated", "collection", "skipped", "protected", "failed"],
        list[AttachmentItem],
        dict[str, str],
    ]:
        """Sync KeePass changes onto an item that already exists in the vault.

        Returns ``(outcome, upload_attachments, stale_by_name)`` where *outcome*
        is one of ``"updated"`` (content PUT), ``"collection"`` (membership-only
        PUT), ``"skipped"`` (no change), ``"protected"`` (a manual Bitwarden edit
        preserved instead of clobbered) or ``"failed"`` (the PUT was rejected);
        *upload_attachments* are the files to (re-)upload -- those the item does
        not have yet plus those whose content changed; and *stale_by_name* maps
        a changed file's name to the id of the stale copy to delete once its
        replacement has been uploaded.

        *kp_uuid* is the source entry's stable id; it keys the dedup cache update
        after a PUT.  *force_update* makes the content PUT fire even when the
        content is unchanged -- used when adopting a legacy item so its missing
        ``KP2BW_ID`` stamp is backfilled.  It still respects ``--no-update`` (the
        PUT is gated by ``self._update_existing``).

        When the item was edited in Bitwarden since kp2bw last wrote it (its
        ``KP2BW_SYNC`` signature no longer matches), the overwrite is skipped and
        ``"protected"`` returned so the manual edit survives -- unless
        ``self._force_update_all`` (``--force-update``) makes KeePass win.  Legacy
        adoption (*force_update*) and unstamped items are never protected.
        """
        name = bw_item["name"]
        item_id = existing["id"]
        outcome: Literal["updated", "collection", "skipped", "protected", "failed"] = (
            "skipped"
        )

        if existing.get("type") == 5 and bw_item["type"] != 5:
            logger.warning(
                "Entry %s no longer yields a native SSH key; preserving its existing SSH item",
                kp_uuid,
            )
            return "failed", [], {}
        # Native types are reconciled only when their mapping is enabled.
        # The dedup index never adopts unstamped non-login items by name.
        if existing.get("type") != BW_ITEM_TYPE_LOGIN and (
            not (existing.get("type") in (2, 3, 4) and self._map_templates)
            and not (existing.get("type") == 5 and self._ssh_rules)
        ):
            logger.log(
                VERBOSE,
                f"-- Entry {name!r}: matched a non-login item, skipping",
            )
            return outcome, [], {}

        if any(is_record_field(field) for field in existing.get("fields") or []) and (
            not item_kp2bw_sync(existing)
            or (self._is_user_modified(existing) and not self._force_update_all)
        ):
            logger.warning(
                "Item %s has modified content or attachment associations; preserving its files. Retry: %s",
                item_id,
                self._retry_item(
                    kp_uuid, item_id, force=bool(item_kp2bw_sync(existing))
                ),
            )
            return "protected", [], {}

        # Content/collection sync. A rejected PUT here is non-fatal: one
        # problematic entry must not abort the whole re-run and strand every
        # entry after it (the same robustness the attachment phase has).
        try:
            # Content sync: PUT only when the KeePass-derived content changed
            # (keeps re-runs idempotent).
            if (
                has_managed_history(existing)
                and self._is_user_modified(existing)
                and not self._force_update_all
            ):
                logger.warning(
                    "Item %s: password history or managed content was edited; preserving your edit",
                    item_id,
                )
                return "protected", [], {}
            update_payload = self._build_update_payload(existing, bw_item)
            content_differs = self._content_differs(existing, update_payload)
            sync_stamp_stale = self._is_user_modified(existing)
            sync_stamp = item_kp2bw_sync(existing)
            stamp_generation = (
                None
                if sync_stamp is None
                else sync_stamp_generation(existing, sync_stamp)
            )
            legacy_sync_stamp = stamp_generation in {"pre_fido2", "legacy"}
            ambiguous_legacy_edit = (
                legacy_sync_stamp
                and content_differs
                and legacy_extensions_differ(existing, update_payload, stamp_generation)
            )
            legacy_ref_status = self._legacy_ref_status(existing, kp_uuid)
            legacy_ref_output = legacy_ref_status == "exact"
            repair_sync_stamp = not content_differs and (
                legacy_sync_stamp or (sync_stamp_stale and legacy_ref_output)
            )
            if self._update_existing and (
                force_update or content_differs or repair_sync_stamp
            ):
                # Protect a manual Bitwarden edit: when the content genuinely
                # diverged (not a forced legacy-adoption PUT) and the item was
                # touched in Bitwarden since kp2bw last wrote it, preserve the
                # edit instead of clobbering it -- unless --force-update makes
                # KeePass win. Skip attachments too: a protected item is left
                # wholly untouched rather than half-synced.
                if (
                    content_differs
                    and not force_update
                    and not self._force_update_all
                    and (
                        sync_stamp_stale
                        or ambiguous_legacy_edit
                        or legacy_ref_status == "diverged"
                    )
                    and not legacy_ref_output
                ):
                    logger.warning(
                        f"-- Entry {name!r}: modified in Bitwarden since the last "
                        f"sync; preserving your edit. To overwrite this item: "
                        f"{self._retry_item(kp_uuid, item_id, force=True)}"
                    )
                    return "protected", [], {}
                if repair_sync_stamp:
                    payload = copy.copy(existing)
                    payload["fields"] = [
                        copy.copy(field) for field in existing["fields"]
                    ]
                    self._stamp_content(payload)
                else:
                    payload = update_payload
                    if legacy_ref_output:
                        existing_login = existing.get("login")
                        payload_login = payload.get("login")
                        if existing_login is not None and payload_login is not None:
                            payload_login["passwordRevisionDate"] = existing_login.get(
                                "passwordRevisionDate"
                            )
                if has_managed_history(payload):
                    fresh = bw.get_item(item_id)
                    if self._content_signature(fresh) != self._content_signature(
                        existing
                    ):
                        logger.warning(
                            "Item %s changed during reconciliation; preserving the concurrent edit",
                            item_id,
                        )
                        return "protected", [], {}
                    revision = fresh.get("revisionDate")
                    if not revision:
                        raise ConversionError(
                            "Native history update requires an item revision"
                        )
                    bw.update_item_if_revision(
                        item_id, payload, expected_revision=revision
                    )
                else:
                    bw.update_item(item_id, payload)
                bw.update_dedup_entry(kp_uuid, payload)
                if legacy_ref_output:
                    logger.log(VERBOSE, f"-- Entry {name!r}: legacy REF state upgraded")
                elif repair_sync_stamp:
                    logger.log(VERBOSE, f"-- Entry {name!r}: sync stamp repaired")
                else:
                    logger.log(
                        VERBOSE, f"-- Entry {name!r}: content updated from KeePass"
                    )
                outcome = "updated"
            elif not fixed_coll_id:
                # Collection-membership-only update (auto/org mode). bw serve
                # returns collectionIds=null on listed items, so in
                # fixed-collection mode we cannot (and need not) do the
                # missing-check — the item is already in the scoped target
                # collection.
                target_colls: list[str] = bw_item.get("collectionIds") or []
                existing_colls: list[str] = existing.get("collectionIds") or []
                missing = [c for c in target_colls if c not in existing_colls]
                if missing:
                    updated_item = copy.copy(existing)
                    updated_item["collectionIds"] = existing_colls + missing
                    bw.update_item(item_id, updated_item)
                    # Keep the cache fresh so a later lookup of this stamp does
                    # not recompute stale collectionIds.
                    bw.update_dedup_entry(kp_uuid, updated_item)
                    logger.log(
                        VERBOSE,
                        f"-- Entry {name!r}: added to {len(missing)} collection(s)",
                    )
                    outcome = "collection"
        except (BitwardenClientError, ConversionError) as exc:
            logger.warning(
                f"-- Entry {name!r}: update failed; no further changes attempted: {exc}"
                f". Retry: {self._retry_item(kp_uuid, item_id, legacy=item_kp2bw_id(existing) is None)}"
            )
            # The content/collection PUT was rejected, so leave the item wholly
            # untouched: syncing attachments now would half-mutate it (stale
            # login fields beside a freshly refreshed notes.txt).
            return "failed", [], {}

        # Attachment sync: upload files the item is missing (so a
        # previously-skipped entry finally gets its notes.txt / long-field / file
        # attachments) *and* refresh files whose content changed but kept the
        # same name, never duplicating an identical one already present.
        upload_atts: list[AttachmentItem] = []
        stale_by_name: dict[str, str] = {}
        if self._update_existing and attachments:
            try:
                full = bw.get_item(item_id)
                records = records_from_fields(full.get("fields") or [])
                if records and (
                    not item_kp2bw_sync(full) or self._is_user_modified(full)
                ):
                    raise ConversionError(
                        "Attachment associations have an invalid sync stamp"
                    )
                sources = self._attachment_sources(attachments)
                previous_records = dict(records)
                full, records = self._recover_checkpoint_uploads(
                    bw, full, sources, records
                )
                plan = plan_attachments(
                    sources,
                    records,
                    [
                        (att["id"], att["fileName"])
                        for att in full.get("attachments") or []
                    ],
                    lambda attachment_id: self._read_checkpoint_attachment(
                        bw, full, sources, records, attachment_id
                    ),
                )
                plan.previous_records = previous_records
                self._prepare_checkpoint_uploads(bw, full, plan)
                self._attachment_plans[item_id] = plan
                upload_atts = list(plan.uploads)
                stale_by_name = {
                    source.filename: plan.stale[source.source_id]
                    for source in plan.uploads
                    if source.source_id in plan.stale
                }
            except (BitwardenClientError, ConversionError) as exc:
                logger.warning(
                    "Could not safely associate attachments on item %s (%s); leaving its files unchanged",
                    item_id,
                    str(exc)
                    if isinstance(exc, ConversionError)
                    else type(exc).__name__,
                )
                return "failed", [], {}

        if outcome == "skipped" and not upload_atts:
            logger.log(
                VERBOSE,
                f"-- Entry {name!r} unchanged in folder {folder!r}, skipping",
            )

        return outcome, upload_atts, stale_by_name

    @staticmethod
    def _attachment_metadata_digest(item: BwItemResponse) -> str:
        return metadata_digest(
            sorted(
                [
                    {
                        "id": attachment["id"],
                        "name": attachment["fileName"],
                        "size": attachment.get("size"),
                    }
                    for attachment in item.get("attachments") or []
                ],
                key=lambda row: row["id"] or "",
            )
        )

    def _prepare_checkpoint_uploads(
        self, bw: BitwardenServeClient, item: BwItemResponse, plan: AttachmentPlan
    ) -> None:
        checkpoint = self._checkpoint
        if checkpoint is None or not plan.uploads:
            return
        entry_id = item_kp2bw_id(item)
        if not entry_id:
            raise ConversionError(
                "Cannot checkpoint an upload without its source identity"
            )
        self._checkpoint_entry_ids[item["id"]] = entry_id.upper()
        prepared: dict[str, SourceFile] = {}
        adopted: set[str] = set()
        updates: list[CheckpointRecord] = []
        for source in plan.uploads:
            previous_id = plan.stale.get(source.source_id)
            previous = plan.records.get(source.source_id)
            if previous_id is not None and (
                previous is None or previous.attachment_id != previous_id
            ):
                raise ConversionError(
                    "Cannot checkpoint a replacement without its previous association"
                )
            filename = transaction_filename(
                source, checkpoint.scope_digest, entry_id, previous_id
            )
            prepared[source.source_id] = replace(source, filename=filename)
            candidates = [
                att["id"]
                for att in item.get("attachments") or []
                if att["fileName"] == filename and att["id"] != previous_id
            ]
            recovered_id: str | None = None
            if candidates:
                if len(candidates) != 1 or any(
                    record.attachment_id == candidates[0]
                    for record in plan.records.values()
                ):
                    raise ConversionError(
                        "Unmapped transaction attachments are ambiguous; preserving them"
                    )
                if bw.get_attachment(item["id"], candidates[0]) != source.data:
                    raise ConversionError(
                        "Unmapped transaction attachment has different contents; preserving it"
                    )
                recovered_id = candidates[0]
                plan.records[source.source_id] = FileRecord(
                    recovered_id,
                    hashlib.sha256(filename.encode()).hexdigest(),
                    source.digest,
                )
                adopted.add(source.source_id)
                if previous_id:
                    self._checkpoint_cleanup.append((item["id"], previous_id, filename))
            updates.append(
                CheckpointRecord(
                    entry_id=entry_id,
                    source_id=source.source_id,
                    source_digest=source.digest,
                    source_size=len(source.data),
                    item_id=item["id"],
                    name_digest=hashlib.sha256(filename.encode()).hexdigest(),
                    phase="verified" if recovered_id else "pending",
                    attachment_id=recovered_id,
                    remote_revision=item.get("revisionDate") if recovered_id else None,
                    remote_metadata_digest=self._attachment_metadata_digest(item)
                    if recovered_id
                    else None,
                    previous_attachment_id=previous_id,
                    previous_digest=previous.digest
                    if previous_id and previous
                    else None,
                    previous_name_digest=previous.name_digest
                    if previous_id and previous
                    else None,
                    before_ids=tuple(
                        att["id"]
                        for att in item.get("attachments") or []
                        if att["id"] != recovered_id
                    ),
                )
            )
        checkpoint.save_many(updates)
        plan.sources = [
            prepared.get(source.source_id, source) for source in plan.sources
        ]
        plan.uploads = [
            prepared[source.source_id]
            for source in plan.uploads
            if source.source_id not in adopted
        ]

    def _recover_checkpoint_uploads(
        self,
        bw: BitwardenServeClient,
        item: BwItemResponse,
        sources: list[SourceFile],
        records: dict[str, FileRecord],
    ) -> tuple[BwItemResponse, dict[str, FileRecord]]:
        checkpoint = self._checkpoint
        entry_id = item_kp2bw_id(item)
        if checkpoint is None or not entry_id:
            return item, records
        effective = dict(records)
        for source in sources:
            pending = checkpoint.records.get(entry_id.upper() + ":" + source.source_id)
            if pending is None or pending.item_id != item["id"]:
                continue
            expected_name = transaction_filename(
                source,
                checkpoint.scope_digest,
                entry_id,
                pending.previous_attachment_id,
            )
            # Ordinary cached files have no transaction suffix. Unchanged
            # transaction files also need no recovery or body download.
            if pending.phase == "mapped" and (
                pending.name_digest
                != hashlib.sha256(expected_name.encode()).hexdigest()
                or pending.reusable(
                    item_id=item["id"],
                    attachment_id=pending.attachment_id or "",
                    source_digest=source.digest,
                    source_size=len(source.data),
                    name_digest=pending.name_digest,
                    revision=item.get("revisionDate") or "",
                    remote_metadata_digest=self._attachment_metadata_digest(item),
                )
            ):
                continue

            def read(attachment_id: str, item_id: str = item["id"]) -> bytes | None:
                try:
                    return bw.get_attachment(item_id, attachment_id)
                except BitwardenAttachmentMissingError:
                    return None

            decision = inspect_pending_upload(
                source,
                pending,
                checkpoint.scope_digest,
                item.get("attachments") or [],
                read,
            )
            if pending.previous_attachment_id is not None:
                previous = next(
                    (
                        att
                        for att in item.get("attachments") or []
                        if att["id"] == pending.previous_attachment_id
                    ),
                    None,
                )
                current_association = records.get(source.source_id)
                if (
                    previous is None
                    and current_association is not None
                    and current_association.attachment_id
                    == pending.previous_attachment_id
                ):
                    raise ConversionError(
                        "The previous attachment was removed while its replacement was pending"
                    )
                if previous is not None and (
                    hashlib.sha256(previous["fileName"].encode()).hexdigest()
                    != pending.previous_name_digest
                    or hashlib.sha256(
                        bw.get_attachment(item["id"], previous["id"])
                    ).hexdigest()
                    != pending.previous_digest
                ):
                    raise ConversionError(
                        "The previous attachment was edited while its replacement was pending"
                    )
            for orphan_id in decision.orphan_ids:
                # Record the discovered slot before removing it. A crash after
                # deletion is recoverable because the stable transaction name
                # is reused and no completed upload is assumed.
                checkpoint.save(replace(pending, phase="slot", attachment_id=orphan_id))
                current = bw.get_item(item["id"])
                if current.get("revisionDate") != item.get(
                    "revisionDate"
                ) or self._attachment_metadata_digest(
                    current
                ) != self._attachment_metadata_digest(item):
                    raise ConversionError(
                        "Item changed before incomplete upload cleanup"
                    )
                bw.delete_attachment(item["id"], orphan_id)
                bw.sync(force=True)
                item = bw.get_item(item["id"])
            if decision.attachment_id is None:
                continue
            association = records.get(source.source_id)
            if association is not None and association.attachment_id not in {
                pending.previous_attachment_id,
                decision.attachment_id,
            }:
                raise ConversionError(
                    "Attachment association changed during checkpoint recovery"
                )
            effective[source.source_id] = FileRecord(
                decision.attachment_id, pending.name_digest, source.digest
            )
            checkpoint.save(
                replace(
                    pending,
                    phase="verified",
                    attachment_id=decision.attachment_id,
                    remote_revision=item.get("revisionDate"),
                    remote_metadata_digest=self._attachment_metadata_digest(item),
                )
            )
            cleanup_ids = list(decision.duplicate_ids)
            if (
                pending.previous_attachment_id
                and pending.previous_attachment_id != decision.attachment_id
                and any(
                    att["id"] == pending.previous_attachment_id
                    for att in item.get("attachments") or []
                )
            ):
                cleanup_ids.append(pending.previous_attachment_id)
            self._checkpoint_cleanup.extend(
                (item["id"], old_id, expected_name) for old_id in cleanup_ids
            )
        return item, effective

    def _read_checkpoint_attachment(
        self,
        bw: BitwardenServeClient,
        item: BwItemResponse,
        sources: list[SourceFile],
        records: dict[str, FileRecord],
        attachment_id: str,
    ) -> bytes:
        checkpoint = self._checkpoint
        entry_id = item_kp2bw_id(item)
        if checkpoint is not None and entry_id:
            for source in sources:
                association = records.get(source.source_id)
                cached = checkpoint.records.get(
                    entry_id.upper() + ":" + source.source_id
                )
                if (
                    association is None
                    or cached is None
                    or association.attachment_id != attachment_id
                ):
                    continue
                if association.digest == source.digest and cached.reusable(
                    item_id=item["id"],
                    attachment_id=attachment_id,
                    source_digest=source.digest,
                    source_size=len(source.data),
                    name_digest=association.name_digest,
                    revision=item.get("revisionDate") or "",
                    remote_metadata_digest=self._attachment_metadata_digest(item),
                ):
                    return source.data
        return bw.get_attachment(item["id"], attachment_id)

    def _save_verified_checkpoint(
        self,
        bw: BitwardenServeClient,
        item_id: str,
        plan: AttachmentPlan,
    ) -> None:
        checkpoint = self._checkpoint
        if checkpoint is None:
            return
        before = bw.get_item(item_id)
        entry_id = item_kp2bw_id(before)
        revision = before.get("revisionDate")
        if not entry_id or not revision:
            raise ConversionError(
                "Cannot checkpoint attachments without source identity and revision"
            )
        associations = records_from_fields(before.get("fields") or [])
        metadata = self._attachment_metadata_digest(before)
        updates: list[CheckpointRecord] = []
        for source in plan.sources:
            association = associations.get(source.source_id)
            if association is None or association.digest != source.digest:
                raise ConversionError(
                    "Cannot checkpoint an unverified attachment association"
                )
            if (
                self._read_checkpoint_attachment(
                    bw, before, plan.sources, associations, association.attachment_id
                )
                != source.data
            ):
                raise ConversionError(
                    "Remote attachment changed before checkpoint verification"
                )
            prior = checkpoint.records.get(entry_id.upper() + ":" + source.source_id)
            updates.append(
                CheckpointRecord(
                    entry_id=entry_id,
                    source_id=source.source_id,
                    source_digest=source.digest,
                    source_size=len(source.data),
                    item_id=item_id,
                    name_digest=association.name_digest,
                    phase="mapped",
                    attachment_id=association.attachment_id,
                    remote_revision=revision,
                    remote_metadata_digest=metadata,
                    previous_attachment_id=(
                        prior.previous_attachment_id if prior else None
                    ),
                    before_ids=prior.before_ids if prior else (),
                    previous_digest=prior.previous_digest if prior else None,
                    previous_name_digest=prior.previous_name_digest if prior else None,
                )
            )
        after = bw.get_item(item_id)
        if (
            after.get("revisionDate") != revision
            or self._attachment_metadata_digest(after) != metadata
        ):
            raise ConversionError("Item changed during checkpoint verification")
        checkpoint.save_many(updates)

    def _delete_checkpoint_copy(
        self, bw: BitwardenServeClient, item_id: str, attachment_id: str, filename: str
    ) -> None:
        checkpoint = self._checkpoint
        if checkpoint is None:
            bw.delete_attachment(item_id, attachment_id)
            return
        matches = [
            record
            for record in checkpoint.records.values()
            if record.item_id == item_id
            and record.name_digest == hashlib.sha256(filename.encode()).hexdigest()
            and record.phase in {"verified", "mapped"}
        ]
        if len(matches) != 1:
            raise ConversionError(
                "Cleanup has no unique verified checkpoint association"
            )
        record = matches[0]
        if attachment_id == record.attachment_id:
            raise ConversionError("Cleanup must not remove the verified replacement")
        old_copy = attachment_id == record.previous_attachment_id
        if not old_copy and attachment_id in record.before_ids:
            raise ConversionError(
                "Cleanup must not remove a pre-existing unrelated file"
            )
        expected_name = record.previous_name_digest if old_copy else record.name_digest
        expected_digest = record.previous_digest if old_copy else record.source_digest
        before = bw.get_item(item_id)
        attachment = next(
            (
                att
                for att in before.get("attachments") or []
                if att["id"] == attachment_id
            ),
            None,
        )
        if attachment is None:
            return
        if (
            hashlib.sha256(attachment["fileName"].encode()).hexdigest() != expected_name
            or hashlib.sha256(bw.get_attachment(item_id, attachment_id)).hexdigest()
            != expected_digest
        ):
            raise ConversionError(
                "Attachment changed before checkpoint cleanup; preserving it"
            )
        after = bw.get_item(item_id)
        if before.get("revisionDate") != after.get(
            "revisionDate"
        ) or self._attachment_metadata_digest(
            before
        ) != self._attachment_metadata_digest(after):
            raise ConversionError(
                "Item changed before checkpoint cleanup; preserving its files"
            )
        bw.delete_attachment(item_id, attachment_id)

    def _persist_attachment_plan(
        self,
        bw: BitwardenServeClient,
        item_id: str,
        plan: AttachmentPlan,
        failed: set[tuple[str, str]],
    ) -> None:
        full = bw.get_item(item_id)
        current = records_from_fields(full.get("fields") or [])
        if current != plan.previous_records or self._is_user_modified(full):
            raise ConversionError("Item changed while saving attachment associations")
        records = dict(plan.records)
        verified: list[CheckpointRecord] = []
        for source in plan.uploads:
            if (item_id, source.filename) in failed:
                continue
            candidates = [
                attachment["id"]
                for attachment in full.get("attachments") or []
                if attachment["fileName"] == source.filename
                and attachment["id"] != plan.stale.get(source.source_id)
                and bw.get_attachment(item_id, attachment["id"]) == source.data
            ]
            if len(candidates) != 1:
                raise ConversionError(
                    "Uploaded attachment cannot be associated uniquely"
                )
            records[source.source_id] = FileRecord(
                candidates[0],
                hashlib.sha256(source.filename.encode()).hexdigest(),
                source.digest,
            )
            if self._checkpoint is not None:
                entry_id = self._checkpoint_entry_ids[item_id]
                pending = self._checkpoint.records[entry_id + ":" + source.source_id]
                verified.append(
                    replace(
                        pending,
                        phase="verified",
                        attachment_id=candidates[0],
                        remote_revision=full.get("revisionDate"),
                        remote_metadata_digest=self._attachment_metadata_digest(full),
                    )
                )
        if self._checkpoint is not None and verified:
            self._checkpoint.save_many(verified)
        if records == current:
            return
        full["fields"] = [
            field
            for field in full.get("fields") or []
            if not (field.get("name") or "").startswith(ATTACHMENT_FIELD_PREFIX)
        ] + fields_from_records(records)
        self._stamp_content(full)
        bw.update_item(item_id, full)
        # The CLI can acknowledge PUT before its local item cache reflects it.
        # Read the server state before authorizing deletion of the old file.
        bw.sync(force=True)
        persisted = bw.get_item(item_id)
        if records_from_fields(persisted.get("fields") or []) != records:
            raise ConversionError("Attachment associations were not persisted")

    def _create_bitwarden_items_for_entries(
        self, client: BitwardenServeClient | None = None
    ) -> int:
        """Create entries via ``bw serve`` HTTP API and upload attachments.

        Returns the count of non-fatal failures (rejected creates + updates +
        attachment uploads).
        """
        logger.info("Connecting and reading existing folders and entries")

        # When a fixed collection ID is given, scope the dedup index to that
        # collection so items that exist in *other* collections are treated as
        # new and are imported into the target collection rather than skipped.
        fixed_coll_id = (
            self._bitwarden_coll_id
            if self._bitwarden_coll_id
            and self._bitwarden_coll_id not in COLLECTION_FOLDER_MODES
            else None
        )

        n_skipped = 0
        n_updated = 0
        n_protected = 0
        n_collection_update = 0
        n_created = 0
        n_create_failed = 0
        n_attachments = 0
        n_attach_failed = 0
        n_update_failed = 0
        n_history = 0
        t_start = time.monotonic()

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        )

        with (
            progress,
            ExitStack() as checkpoint_resources,
            (
                nullcontext(client)
                if client is not None
                else BitwardenServeClient(
                    self._bitwarden_password,
                    org_id=self._bitwarden_organization_id,
                    collection_id=fixed_coll_id,
                )
            ) as bw,
        ):
            if any(
                self._unpack_entry(value)[2]["type"] == 5
                for value in self._entries.values()
            ):
                bw.require_ssh_supported()

            if self._checkpoint_path:
                server, account = bw.checkpoint_identity()
                self._checkpoint = checkpoint_resources.enter_context(
                    AttachmentCheckpoint(
                        Path(self._checkpoint_path),
                        CheckpointScope(
                            server,
                            account,
                            self._source_scope_id,
                            self._bitwarden_organization_id,
                            self._bitwarden_coll_id,
                        ),
                    )
                )
            # --- Phase 1: Partition entries and resolve collections ----------
            import_entries: dict[str, tuple[str | None, BwItemCreate]] = {}
            attachment_map: dict[str, list[AttachmentItem]] = {}
            # Existing items needing only missing attachments uploaded:
            # (item_id, [attachments]).
            existing_uploads: list[tuple[str, list[AttachmentItem]]] = []
            # (item_id, filename) pairs already queued this run, so two KeePass
            # entries sharing one (folder, name) can't upload the same file
            # twice while each entry's *unique* attachments are still uploaded.
            queued_atts: set[tuple[str, str]] = set()
            # Stale copies to remove after their replacement uploads, as
            # (item_id, attachment_id, filename); the delete only fires once the
            # matching (item_id, filename) upload has succeeded.
            pending_deletes: list[tuple[str, str, str]] = []

            task1 = progress.add_task("Processing entries", total=len(self._entries))
            for key, entry_value in self._entries.items():
                folder, firstlevel, bw_item, attachments = self._unpack_entry(
                    entry_value
                )

                # Resolve collection (mutates bw_item). A dropped collection
                # POST is non-fatal: skip just this entry rather than abort the
                # whole loop and strand every entry after it (issue #24).
                if not self._resolve_collection_safely(bw, bw_item, folder, firstlevel):
                    n_create_failed += 1
                    progress.advance(task1)
                    continue

                # Stable-identity dedup: match this entry to its Bitwarden item
                # by the KeePass UUID stamp first; failing that, adopt an
                # unstamped legacy item sharing (folder, name) and backfill the
                # stamp. Only when neither matches is a new item created — so
                # distinct entries that share a title each get their own item
                # instead of collapsing onto one (the old (folder, title) bug).
                existing = (
                    bw.get_item(self._selection.destination_id)
                    if self._selection is not None and self._selection.destination_id
                    else None
                    if self._selection is not None
                    else bw.get_item_by_uuid(key)
                )
                adopted = False
                if existing is None and self._selection is None:
                    # Fallback for pre-stamp legacy items only. Keyed on the
                    # KeePass (folder, name); under --no-folder those items were
                    # created with folderId=None, so this folder-based claim can
                    # miss them and re-create. Harmless for anything kp2bw wrote
                    # since: the UUID-stamp match above is folder-independent and
                    # keeps re-runs idempotent.
                    existing = bw.claim_legacy_item(folder, bw_item["name"])
                    adopted = existing is not None
                if existing is not None:
                    item_id = existing["id"]
                    outcome, upload_atts, stale_by_name = self._reconcile_existing_item(
                        bw,
                        existing,
                        folder,
                        bw_item,
                        attachments,
                        fixed_coll_id=fixed_coll_id,
                        kp_uuid=key,
                        force_update=adopted,
                    )
                    if outcome == "updated":
                        n_updated += 1
                        n_history += imported_history_count(
                            self._build_update_payload(existing, bw_item)
                        )
                    elif outcome == "collection":
                        n_collection_update += 1
                    elif outcome == "protected":
                        n_protected += 1
                    elif outcome == "failed":
                        n_update_failed += 1
                    else:  # "skipped" — content unchanged (attachments, if any,
                        # are reported separately via the attachment counters).
                        n_skipped += 1
                    # Queue each file once per item, so two KeePass entries
                    # collapsing to the same vault item don't upload a shared
                    # file twice yet still contribute their unique files. A
                    # changed file's stale copy is scheduled for deletion only
                    # alongside the queued replacement upload.
                    unique_atts: list[AttachmentItem] = []
                    for att in upload_atts:
                        fname = self._attachment_filename(att)
                        pair = (item_id, fname)
                        if pair not in queued_atts:
                            queued_atts.add(pair)
                            unique_atts.append(att)
                            old_id = stale_by_name.get(fname)
                            if old_id is not None:
                                pending_deletes.append((item_id, old_id, fname))
                    if unique_atts:
                        existing_uploads.append((item_id, unique_atts))
                    progress.advance(task1)
                    continue

                import_entries[key] = (folder, bw_item)
                if attachments:
                    attachment_map[key] = attachments
                progress.advance(task1)

            # --- Phase 2: Create items via bw serve HTTP API ----------------
            if import_entries:
                task2 = progress.add_task("Creating items", total=len(import_entries))

                def _on_created() -> None:
                    nonlocal n_created
                    n_created += 1
                    progress.advance(task2)

                def _on_create_failed(_key: str, _exc: BitwardenClientError) -> None:
                    # A rejected create is non-fatal (issue #24): tally it and
                    # advance the bar so a partial batch still completes the run.
                    nonlocal n_create_failed
                    n_create_failed += 1
                    progress.advance(task2)

                key_to_id = bw.create_items_batch(
                    import_entries,
                    on_item_created=_on_created,
                    on_item_failed=_on_create_failed,
                    create_folders=self._create_folders,
                )
            else:
                key_to_id = {}

            n_history += sum(
                imported_history_count(import_entries[key][1]) for key in key_to_id
            )

            # --- Phase 3: Parallel attachment uploads -----------------------
            # Newly-created items (resolve their server-assigned IDs) and
            # existing items missing attachments share one upload pass.
            upload_items: list[tuple[str, list[tuple[str, bytes]]]] = []
            new_item_uploads = False
            for key, new_atts in attachment_map.items():
                item_id = key_to_id.get(key)
                if not item_id:
                    _folder, miss_item = import_entries[key]
                    logger.warning(
                        f"Could not find item ID for {miss_item['name']!r} "
                        f"in folder {_folder!r} for attachment upload"
                    )
                    continue
                new_item_uploads = True
                self._attachment_plans[item_id] = plan_attachments(
                    self._attachment_sources(new_atts),
                    {},
                    [],
                    lambda _: b"",
                )
                plan = self._attachment_plans[item_id]
                if self._checkpoint is not None:
                    self._prepare_checkpoint_uploads(bw, bw.get_item(item_id), plan)
                upload_items.append((
                    item_id,
                    [self._materialise_attachment(a) for a in plan.uploads],
                ))
            for item_id, existing_atts in existing_uploads:
                upload_items.append((
                    item_id,
                    [self._materialise_attachment(a) for a in existing_atts],
                ))

            # A just-created item can be momentarily unresolvable by bw serve's
            # attachment endpoint, which resolves `itemid` from its local vault
            # cache; sync so freshly created IDs are visible before uploading to
            # them. (upload_attachment also self-heals with a sync-and-retry.)
            if new_item_uploads:
                self._sync_safely(bw)

            failed: list[tuple[str, str]] = []
            if upload_items:
                total_files = sum(len(fps) for _, fps in upload_items)
                task3 = progress.add_task(
                    "Uploading attachments", total=len(upload_items)
                )
                failed = bw.upload_attachments(upload_items)
                if self._checkpoint is not None:
                    completed: list[CheckpointRecord] = []
                    for item_id, plan in self._attachment_plans.items():
                        for source in plan.uploads:
                            if (item_id, source.filename) not in failed:
                                key = (
                                    self._checkpoint_entry_ids[item_id]
                                    + ":"
                                    + source.source_id
                                )
                                completed.append(
                                    replace(
                                        self._checkpoint.records[key], phase="uploaded"
                                    )
                                )
                    self._checkpoint.save_many(completed)
                n_attach_failed = len(failed)
                n_attachments = total_files - n_attach_failed
                progress.update(task3, completed=len(upload_items))

            # Persist source -> destination IDs before removing any old copy.
            # A failed metadata write leaves both files intact and makes the run
            # fail; acknowledged bytes alone never authorize a stale delete.
            failed_uploads = set(failed)
            for item_id, plan in self._attachment_plans.items():
                try:
                    self._persist_attachment_plan(bw, item_id, plan, failed_uploads)
                except (BitwardenClientError, ConversionError) as exc:
                    n_update_failed += 1
                    failed_uploads.update(
                        (item_id, source.filename) for source in plan.sources
                    )
                    logger.warning(
                        "Could not persist attachment associations on item %s (%s); retaining old copies",
                        item_id,
                        str(exc)
                        if isinstance(exc, ConversionError)
                        else type(exc).__name__,
                    )
            deleted_files = False
            for item_id, old_id, fname in dict.fromkeys([
                *pending_deletes,
                *self._checkpoint_cleanup,
            ]):
                if (item_id, fname) in failed_uploads:
                    continue
                try:
                    self._delete_checkpoint_copy(bw, item_id, old_id, fname)
                    deleted_files = True
                except BitwardenClientError, ConversionError:
                    n_attach_failed += 1
                    failed_uploads.add((item_id, fname))
                    logger.warning(
                        "Could not remove a stale attachment on item %s; old copy retained",
                        item_id,
                    )

            if deleted_files and self._checkpoint is not None:
                bw.sync(force=True)
                _ = bw.list_items()
            for item_id, plan in self._attachment_plans.items():
                if any(
                    (item_id, source.filename) in failed_uploads
                    for source in plan.sources
                ):
                    continue
                try:
                    self._save_verified_checkpoint(bw, item_id, plan)
                except (BitwardenClientError, ConversionError) as exc:
                    n_update_failed += 1
                    logger.warning(
                        "Could not checkpoint verified attachments on item %s (%s)",
                        item_id,
                        type(exc).__name__,
                    )

        elapsed = time.monotonic() - t_start
        _print_summary(
            elapsed,
            n_created,
            n_updated,
            n_skipped,
            n_protected,
            n_collection_update,
            n_attachments,
            n_update_failed,
            n_attach_failed,
            n_create_failed,
            n_history,
        )
        return n_update_failed + n_attach_failed + n_create_failed

    def preview(self, target: BitwardenServeClient | None = None) -> MigrationPreview:
        """Describe source conversion without opening a destination client."""
        self._selection = None
        if self._selected_entry_id is not None or self._selected_item_id is not None:
            if target is None:
                if self._selected_item_id is not None:
                    raise ConversionError("Item selection requires target inspection")
                assert self._selected_entry_id is not None
                self._selection = ItemSelection(
                    source_uuid(self._selected_entry_id), None
                )
            else:
                fixed_collection = self._bitwarden_coll_id
                if fixed_collection in COLLECTION_FOLDER_MODES:
                    fixed_collection = None
                visible = target.list_items()
                scoped = target.list_items(
                    organization_id=self._bitwarden_organization_id,
                    collection_id=fixed_collection,
                )
                self._selection = resolve_selection(
                    self._selected_entry_id,
                    self._selected_item_id,
                    visible,
                    {item["id"] for item in scoped},
                )
        self._preview_sources = {}
        self._preview_groups = []
        self._preview_failures = {}
        self._previewing = True
        failed = False
        try:
            self._prepare_entries()
        except ConversionError:
            # Individual diagnostics are added by preparation. Do not copy exception
            # strings: some third-party failures contain source values.
            failed = True
        finally:
            self._previewing = False
        result = MigrationPreview([], groups=self._preview_groups)
        if failed:
            result.blockers.append(
                "Source preparation failed; migration cannot execute this plan"
            )
        for identifier, inventory in self._preview_sources.items():
            if self._selection is not None and identifier != self._selection.source_id:
                continue
            value = self._entries.get(identifier)
            resolved = self._resolved_ref_items.get(identifier)
            outcome: Literal[
                "planned", "merged", "excluded", "unresolved", "blocked"
            ] = (
                "blocked"
                if failed
                else "planned"
                if value is not None
                else "merged"
                if resolved is not None
                else "unresolved"
                if identifier in self._resolved_ref_items
                else "excluded"
            )
            entry = PreviewEntry(identifier, outcome, source=inventory)
            if problems := self._preview_failures.get(identifier):
                entry.outcome = "blocked"
                entry.blockers.extend(problems)
            if failed:
                entry.blockers.append("Source preparation did not finish")
            elif outcome == "unresolved":
                entry.blockers.append(
                    "Resolve this entry's KeePass references before migration"
                )
            if value is not None:
                item = self._unpack_entry(value)[2]
                describe_payload(entry, item, self._attachment_sources(value[3]))
                if self._checkpoint_path and target is None:
                    entry.attachments = [
                        replace(a, filename_final=False) for a in entry.attachments
                    ]
                if inventory["passkey_fields"] and not entry.passkeys:
                    entry.blockers.append(
                        "Source passkey was not converted to a native passkey; repair its attributes or choose an explicit fallback"
                    )
                if (
                    inventory["tags"] or inventory["expiry"]
                ) and not self._migrate_metadata:
                    entry.omissions.append(
                        "Tags and expiry metadata disabled by --no-metadata"
                    )
            elif resolved is not None:
                entry.destination_source_id = next(
                    (key for key, value in self._entries.items() if value is resolved),
                    None,
                )
            for category in (
                "custom_icons",
                "builtin_icons",
                "autotype_associations",
                "autotype_sequences",
            ):
                if inventory[category]:
                    entry.omissions.append(f"{category}: no destination representation")
            if inventory["history_records"] and not self._archive_history:
                entry.omissions.append(
                    "Full historical records are omitted; use --archive-history to preserve them"
                )
            if entry.blockers and entry.outcome != "unresolved":
                entry.outcome = "blocked"
            result.entries.append(entry)
        if target is not None and not result.blockers:
            self._compare_preview(result, target)
        return result

    def _compare_preview(
        self, result: MigrationPreview, target: BitwardenServeClient
    ) -> None:
        """Reuse execution reconciliation with writes confined to local snapshots."""
        fixed_collection = self._bitwarden_coll_id
        if fixed_collection in COLLECTION_FOLDER_MODES:
            fixed_collection = None
        remote = target.list_items(
            organization_id=self._bitwarden_organization_id,
            collection_id=fixed_collection,
        )
        folders = {
            identifier: name for name, identifier in target.list_folders().items()
        }
        collections = (
            target.list_collections() if self._bitwarden_organization_id else {}
        )
        transport = PreviewTransport(
            target.get_item, target.get_attachment, target.validate_item_update
        )
        ssh_blocker = False
        if any(
            entry.item_type == 5 and entry.outcome == "planned"
            for entry in result.entries
        ):
            try:
                target.require_ssh_supported()
            except BitwardenClientError:
                ssh_blocker = True
        claimed: set[str] = set()
        previous_plans = self._attachment_plans
        self._attachment_plans = {}
        previous_checkpoint = self._checkpoint
        previous_cleanup = self._checkpoint_cleanup
        previous_entry_ids = self._checkpoint_entry_ids
        self._checkpoint_cleanup = []
        self._checkpoint_entry_ids = {}
        self._checkpoint = None
        try:
            if self._checkpoint_path:
                server, account = target.checkpoint_identity()
                self._checkpoint = PreviewCheckpoint(
                    Path(self._checkpoint_path),
                    CheckpointScope(
                        server,
                        account,
                        self._source_scope_id,
                        self._bitwarden_organization_id,
                        self._bitwarden_coll_id,
                    ),
                )
            for entry in result.entries:
                if entry.outcome != "planned" or entry.blockers:
                    continue
                if entry.item_type == 5 and ssh_blocker:
                    entry.outcome = "blocked"
                    entry.blockers.append(
                        "The destination CLI, server or organization policy does not allow verified native SSH support"
                    )
                    continue
                folder, firstlevel, source_item, attachments = self._unpack_entry(
                    self._entries[entry.source_id]
                )
                desired = copy.deepcopy(source_item)
                collection_name = (
                    folder
                    if self._bitwarden_coll_id == NESTED_COLLECTION_MODE
                    else firstlevel
                )
                if (
                    self._bitwarden_coll_id in COLLECTION_FOLDER_MODES
                    and collection_name
                ):
                    desired["collectionIds"] = [
                        collections.get(collection_name, "preview-new-collection")
                    ]
                elif fixed_collection:
                    desired["collectionIds"] = [fixed_collection]
                matches = [
                    item for item in remote if item_kp2bw_id(item) == entry.source_id
                ]
                adopted = False
                if self._selection is not None:
                    matches = [
                        item
                        for item in remote
                        if item["id"] == self._selection.destination_id
                    ]
                if not matches and self._selection is None:
                    matches = [
                        item
                        for item in remote
                        if item["id"] not in claimed
                        and not item_kp2bw_id(item)
                        and item.get("type") == 1
                        and item.get("name") == desired["name"]
                        and folders.get(item.get("folderId") or "") == folder
                    ]
                    adopted = bool(matches)
                if len(matches) > 1:
                    entry.outcome = "blocked"
                    entry.blockers.append(
                        "Multiple destination items match this source identity or legacy folder/name"
                    )
                    continue
                if not matches:
                    entry.outcome = "create"
                    if self._checkpoint is not None:
                        sources = self._attachment_sources(attachments)
                        entry.attachments = describe_attachments([
                            replace(
                                source,
                                filename=transaction_filename(
                                    source,
                                    self._checkpoint.scope_digest,
                                    entry.source_id,
                                    None,
                                ),
                            )
                            for source in sources
                        ])
                    entry.uploads = len(entry.attachments)
                    entry.upload_bytes = sum(a.bytes for a in entry.attachments)
                    continue
                existing = transport.get_item(matches[0]["id"])
                claimed.add(existing["id"])
                entry.target_id = existing["id"]
                outcome, uploads, _ = self._reconcile_existing_item(
                    transport,
                    existing,
                    folder,
                    desired,
                    attachments,
                    fixed_coll_id=fixed_collection,
                    kp_uuid=entry.source_id,
                    force_update=adopted,
                )
                entry.uploads = len(uploads)
                plan = self._attachment_plans.get(existing["id"])
                if plan is not None:
                    entry.attachments = describe_attachments(plan.sources)
                entry.cleanup_attachments = sum(
                    item_id == existing["id"]
                    for item_id, _ in transport.deleted_attachments
                )
                entry.upload_bytes = sum(
                    len(self._materialise_attachment(a)[1]) for a in uploads
                )
                if outcome == "failed":
                    entry.outcome = "blocked"
                    entry.blockers.append(
                        "Destination reconciliation rejected the item; inspect capabilities, edit protection and attachment associations"
                    )
                elif outcome == "protected":
                    entry.outcome = "protected"
                elif (
                    outcome in {"updated", "collection"}
                    or uploads
                    or entry.cleanup_attachments
                    or (plan is not None and plan.records != plan.previous_records)
                ):
                    entry.outcome = "update"
                else:
                    entry.outcome = "unchanged"
        finally:
            self._checkpoint = previous_checkpoint
            self._checkpoint_cleanup = previous_cleanup
            self._checkpoint_entry_ids = previous_entry_ids
            self._attachment_plans = previous_plans
        changing = [
            entry for entry in result.entries if entry.outcome in {"create", "update"}
        ]
        if changing:
            try:
                policy_blockers = target.item_policy_blockers({
                    entry.item_type for entry in changing if entry.item_type is not None
                })
            except BitwardenClientError:
                policy_blockers = {
                    entry.item_type: "Organization policies could not be verified; refresh the active CLI profile and retry"
                    for entry in changing
                    if entry.item_type is not None
                }
            for entry in changing:
                if entry.item_type is not None and (
                    reason := policy_blockers.get(entry.item_type)
                ):
                    entry.outcome = "blocked"
                    entry.blockers.append(reason)
        uploading = [
            entry for entry in result.entries if entry.uploads and not entry.blockers
        ]
        if uploading:
            try:
                capability = target.attachment_capability()
            except BitwardenClientError:
                capability = AttachmentCapability(
                    None,
                    reason="Attachment entitlement and free storage could not be verified from the active CLI profile",
                )
            result.attachment_capability = capability
            required = sum(entry.upload_bytes for entry in uploading)
            exceeds_total = (
                capability.storage_limit_bytes is not None
                and required > capability.storage_limit_bytes
            )
            if capability.allowed is False or exceeds_total:
                for entry in uploading:
                    entry.outcome = "blocked"
                    entry.blockers.append(
                        "Planned attachment bytes exceed the organization's entire storage allowance"
                        if exceeds_total
                        else capability.reason
                    )
        result.target_inspected = True

    def _prepare_entries(self) -> None:
        """Build and validate migration payloads without opening a destination."""
        # load keepass data from database
        self._load_keepass_data()

        # resolve {REF:...} stuff
        self._resolve_entries_with_references()

        if self._map_templates:
            for identifier, entry_value in self._entries.items():
                if rule := self._entry_templates.get(identifier):
                    item = self._unpack_entry(entry_value)[2]
                    for warning in apply_template(item, rule):
                        logger.warning("Entry %s: %s", identifier, warning)
                        if self._previewing:
                            self._preview_failures.setdefault(identifier, []).append(
                                warning
                            )

        for identifier, entry_value in self._entries.items():
            if selected := self._ssh_sources.get(identifier):
                rule, source_fields = selected
                folder, firstlevel, item, attachments = self._unpack_entry(entry_value)
                fields = {
                    **source_fields,
                    "UserName": item["login"]["username"],
                    "Password": item["login"]["password"],
                }
                files, warnings = apply_ssh_rule(item, fields, rule)
                for warning in warnings:
                    logger.warning("Entry %s: %s", identifier, warning)
                    if self._previewing:
                        self._preview_failures.setdefault(identifier, []).append(
                            warning
                        )
                self._entries[identifier] = (
                    folder,
                    firstlevel,
                    item,
                    [*attachments, *files],
                )

        # REF merging may add URIs or TOTP after initial conversion. Validate
        # every final item before opening the destination transport.
        for identifier, entry in self._entries.items():
            try:
                validate_item(self._unpack_entry(entry)[2])
            except FieldLimitError as exc:
                if not self._previewing:
                    raise
                self._preview_failures.setdefault(identifier, []).append(str(exc))

    def convert(self) -> int:
        """Run the full KeePass-to-Bitwarden migration pipeline.

        Returns the number of non-fatal failures (rejected entry creates plus
        updates plus attachment uploads); ``0`` means everything succeeded.
        """
        self._attachment_plans.clear()
        if self._selected_entry_id is not None or self._selected_item_id is not None:
            fixed_collection = self._bitwarden_coll_id
            if fixed_collection in COLLECTION_FOLDER_MODES:
                fixed_collection = None
            with BitwardenServeClient(
                self._bitwarden_password,
                org_id=self._bitwarden_organization_id,
                collection_id=fixed_collection,
            ) as bw:
                visible = bw.list_items()
                scoped = bw.list_items(
                    organization_id=self._bitwarden_organization_id,
                    collection_id=fixed_collection,
                )
                self._selection = resolve_selection(
                    self._selected_entry_id,
                    self._selected_item_id,
                    visible,
                    {item["id"] for item in scoped},
                )
                self._prepare_entries()
                selected = self._entries.get(self._selection.source_id)
                if selected is None:
                    raise ConversionError(
                        "Selected entry could not be resolved; no items written"
                    )
                self._entries = {self._selection.source_id: selected}
                return self._create_bitwarden_items_for_entries(bw)

        self._prepare_entries()

        # store aggregated entries in bw
        return self._create_bitwarden_items_for_entries()
