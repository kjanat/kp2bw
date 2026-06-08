import base64
import binascii
import copy
import logging
import time
from itertools import islice
from typing import Literal

from pykeepass import Attachment, Entry, Group, PyKeePass
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
from ._console import console
from .bw_serve import BitwardenServeClient
from .bw_types import (
    BwFido2Credential,
    BwField,
    BwItemCreate,
    BwItemLogin,
    BwItemResponse,
    BwUri,
)
from .exceptions import BitwardenClientError, ConversionError
from .otp import resolve_otp

logger = logging.getLogger(__name__)

KP_REF_IDENTIFIER: str = "{REF:"
MAX_BW_ITEM_LENGTH: int = 10 * 1000
KPEX_PASSKEY_PREFIX: str = "KPEX_PASSKEY_"
# Bitwarden item type for login entries (1=login, 2=secureNote, 3=card,
# 4=identity).  kp2bw only ever creates and content-syncs login items.
BW_ITEM_TYPE_LOGIN: int = 1

# Attachment-like: real pykeepass Attachment or (key, value) tuple for long fields
type AttachmentItem = Attachment | tuple[str, str]

# Entry storage: (folder, firstlevel, bw_item, attachments)
type EntryValue = tuple[str | None, str | None, BwItemCreate, list[AttachmentItem]]

# Custom field spec: (value, type_int)  e.g. ("secret", 1)
# Field types: 0=text, 1=hidden, 2=boolean, 3=linked
type FieldSpec = tuple[str | None, Literal[0, 1, 2, 3]]


def _print_summary(
    elapsed: float,
    n_created: int,
    n_updated: int,
    n_skipped: int,
    n_collection_update: int,
    n_attachments: int,
    n_update_failed: int,
    n_attach_failed: int,
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
                n_collection_update,
                n_attachments,
                n_update_failed,
                n_attach_failed,
                1,
            )
        )
    )
    console.print(f"  [green]{n_created:{w}d}[/green] created")
    if n_updated:
        console.print(f"  [blue]{n_updated:{w}d}[/blue] updated (changed in KeePass)")
    if n_skipped:
        console.print(f"  [dim]{n_skipped:{w}d}[/dim] skipped (unchanged)")
    if n_collection_update:
        console.print(
            f"  [yellow]{n_collection_update:{w}d}[/yellow] added to collection"
        )
    if n_attachments:
        console.print(f"  [cyan]{n_attachments:{w}d}[/cyan] attachments uploaded")
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
    _kp_ref_entries: list[Entry]
    _entries: dict[str, EntryValue]
    _member_reference_resolving_dict: dict[str, str]

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
    ) -> None:
        """Initialise the converter with KeePass source and Bitwarden target settings."""
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
        self._kp_ref_entries = []
        self._entries = {}

        self._member_reference_resolving_dict = {"username": "U", "password": "P"}

    @staticmethod
    def _convert_pem_to_base64url(pem_key: str) -> str:
        """Convert a PEM-encoded private key to base64url (no padding)."""
        lines = pem_key.strip().splitlines()
        # Strip PEM header/footer lines
        b64_data = "".join(line for line in lines if not line.startswith("-----"))
        raw_bytes = base64.b64decode(b64_data)
        return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode()

    def _build_fido2_credentials(self, entry: Entry) -> list[BwFido2Credential] | None:
        """Extract KeePassXC passkey attributes and convert to Bitwarden fido2Credentials format."""
        props: dict[str, str | None] = entry.custom_properties

        credential_id: str | None = props.get("KPEX_PASSKEY_CREDENTIAL_ID")
        private_key_pem: str | None = props.get("KPEX_PASSKEY_PRIVATE_KEY_PEM")

        if not credential_id or not private_key_pem:
            return None

        try:
            key_value = self._convert_pem_to_base64url(private_key_pem)
        except ValueError, binascii.Error:
            logger.warning(
                f"Could not convert passkey private key for entry: {entry.title}"
            )
            return None

        creation_date: str | None = entry.ctime.isoformat() if entry.ctime else None

        cred: BwFido2Credential = {
            "credentialId": credential_id,
            "keyType": "public-key",
            "keyAlgorithm": "ECDSA",
            "keyCurve": "P-256",
            "keyValue": key_value,
            "rpId": props.get("KPEX_PASSKEY_RELYING_PARTY") or "",
            "rpName": props.get("KPEX_PASSKEY_RELYING_PARTY") or "",
            "userHandle": props.get("KPEX_PASSKEY_USER_HANDLE") or "",
            "userName": props.get("KPEX_PASSKEY_USERNAME") or entry.username or "",
            "userDisplayName": props.get("KPEX_PASSKEY_USERNAME")
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
    ) -> BwItemCreate:
        """Build a Bitwarden item dict from individual entry fields."""
        uris: list[BwUri] = [BwUri(uri=url, match=None)] if url else []
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
            if value is not None and len(value) <= MAX_BW_ITEM_LENGTH
        ]

        return BwItemCreate(
            organizationId=self._bitwarden_organization_id,
            collectionIds=[],
            folderId=None,
            type=1,
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

    def _build_metadata_fields(self, entry: Entry) -> dict[str, FieldSpec]:
        """Build extra custom fields for KeePass metadata (tags, expiry, timestamps)."""
        fields: dict[str, FieldSpec] = {}

        # Tags
        if entry.tags:
            fields["KeePass Tags"] = (", ".join(entry.tags), 0)

        # Expiry
        if entry.expires and entry.expiry_time:
            fields["Expires"] = (entry.expiry_time.isoformat(), 0)

        # Timestamps
        if entry.ctime:
            fields["Created"] = (entry.ctime.isoformat(), 0)
        if entry.mtime:
            fields["Modified"] = (entry.mtime.isoformat(), 0)

        return fields

    def _add_bw_entry_to_entries_dict(
        self, entry: Entry, custom_protected: list[str] | None
    ) -> None:
        """Convert a KeePass entry into a Bitwarden item and store it in ``_entries``."""
        folder = self._generate_folder_name(entry)
        prefix = ""
        if folder and self._path2name:
            prefix = self._generate_prefix(entry, self._path2nameskip)

        if custom_protected is None:
            custom_protected = []

        custom_props = entry.custom_properties

        # Resolve TOTP/HOTP from entry.otp or the KeePass TimeOtp-*/HmacOtp-*
        # custom fields.  This decides which fields are folded into login.totp
        # (and must be dropped here) and which secrets must remain hidden.
        otp_result = resolve_otp(
            entry.otp, custom_props, entry_label=entry.title or "_untitled"
        )
        for warning in otp_result.warnings:
            logger.warning(f"{entry.title or '_untitled'}: {warning}")

        custom_properties: dict[str, FieldSpec] = {}
        for key, value in custom_props.items():
            # Skip passkey attributes and OTP fields folded into login.totp.
            if key.startswith(KPEX_PASSKEY_PREFIX) or key in otp_result.consumed_keys:
                continue
            if key in otp_result.hidden_keys or key in custom_protected:
                custom_properties[key] = (value, 1)
            else:
                custom_properties[key] = (value, 0)

        # Add metadata fields (tags, expiry, timestamps) if enabled
        if self._migrate_metadata:
            custom_properties.update(self._build_metadata_fields(entry))

        # Build FIDO2/passkey credentials from KeePassXC attributes
        fido2_credentials = self._build_fido2_credentials(entry)
        if fido2_credentials:
            logger.log(VERBOSE, f"  Migrating passkey for entry: {entry.title}")

        # Build notes, prepending [EXPIRED] marker if applicable
        notes = ""
        if entry.notes and len(entry.notes) <= MAX_BW_ITEM_LENGTH:
            notes = entry.notes
        if entry.expired:
            expired_prefix = "[EXPIRED] "
            notes = expired_prefix + notes

        title: str = prefix + entry.title if entry.title else prefix + "_untitled"
        firstlevel = self._get_folder_firstlevel(entry)

        bw_item_object = self._create_bw_python_object(
            title=title,
            notes=notes,
            url=entry.url if entry.url else "",
            totp=otp_result.totp or "",
            username=entry.username if entry.username else "",
            password=entry.password if entry.password else "",
            custom_properties=custom_properties,
            fido2_credentials=fido2_credentials,
        )

        # get attachments to store later on -- never materialise a passkey or an
        # OTP secret (consumed or hidden) as a plaintext .txt attachment.
        attachments: list[AttachmentItem] = [
            (key, value)
            for key, value in custom_props.items()
            if value is not None
            and len(value) > MAX_BW_ITEM_LENGTH
            and not key.startswith(KPEX_PASSKEY_PREFIX)
            and key not in otp_result.consumed_keys
            and key not in otp_result.hidden_keys
        ]

        if entry.notes and len(entry.notes) > MAX_BW_ITEM_LENGTH:
            attachments.append(("notes", entry.notes))

        entry_key: str = str(entry.uuid).replace("-", "").upper()
        if entry.attachments:
            attachments += entry.attachments

        self._entries[entry_key] = (
            folder,
            firstlevel,
            bw_item_object,
            attachments,
        )

    def _parse_kp_ref_string(self, ref_string: str) -> tuple[str, str, str]:
        """Parse a ``{REF:...}`` string into ``(field, lookup_mode, uuid)``."""
        # {REF:U@I:CFC0141068E83547BCEEAF0C1ADABAE0}
        tokens = ref_string.split(":")

        if len(tokens) != 3:
            raise ConversionError("Invalid REF string found")

        ref_compare_string = tokens[2][:-1]
        field_referenced, lookup_mode = tokens[1].split("@")

        return (field_referenced, lookup_mode, ref_compare_string)

    def _get_referenced_entry(
        self, lookup_mode: str, ref_compare_string: str
    ) -> EntryValue:
        """Look up a previously parsed entry by UUID or other reference mode."""
        if lookup_mode == "I":
            # KP_ID lookup
            try:
                return self._entries[ref_compare_string.upper()]
            except KeyError:
                logger.warning(f"!! - Could not resolve REF to {ref_compare_string} !!")
                raise
        else:
            raise ConversionError("Unsupported REF lookup_mode")

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
        kp = PyKeePass(
            filename=self._keepass_file_path,
            password=self._keepass_password,
            keyfile=self._keepass_keyfile_path,
        )

        # reset data structures
        self._kp_ref_entries = []
        self._entries = {}

        # Identify recycle bin group for filtering
        recyclebin_group: Group | None = kp.recyclebin_group

        entries: list[Entry] = kp.entries or []
        total_entries: int = len(entries)
        skipped_recyclebin = 0
        skipped_expired = 0

        logger.info(f"Found {total_entries} entries in KeePass DB. Parsing now...")
        for entry in entries:
            # Skip recycle bin entries unless explicitly included
            if not self._include_recyclebin and self._is_in_recyclebin(
                entry, recyclebin_group
            ):
                skipped_recyclebin += 1
                continue

            # Skip expired entries if requested
            if self._skip_expired and entry.expired:
                skipped_expired += 1
                logger.log(VERBOSE, f"Skipping expired entry: {entry.title}")
                continue

            # prevent not iterable errors at "in" checks
            username: str = entry.username if entry.username else ""
            password: str = entry.password if entry.password else ""

            # Skip REFs as ID might not be in dict yet
            if KP_REF_IDENTIFIER in username or KP_REF_IDENTIFIER in password:
                self._kp_ref_entries.append(entry)
                continue

            # Build per-entry list of protected custom properties
            custom_protected: list[str] = [
                field
                for field in entry.custom_properties
                if (
                    elem := entry._xpath(
                        f'String[Key[text()="{field}"]]/Value', first=True
                    )
                )
                is not None
                and elem.attrib.get("Protected", "False") == "True"
            ]

            # Normal entry
            if self._import_tags:
                for tag in self._import_tags:
                    if tag in entry.tags:
                        self._add_bw_entry_to_entries_dict(entry, custom_protected)
                        break
            else:
                self._add_bw_entry_to_entries_dict(entry, custom_protected)

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
        for kp_entry in self._kp_ref_entries:
            try:
                # replace values
                replaced_entries: list[BwItemCreate] = []
                ref_entry: BwItemCreate | None = None
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

                        replaced_entries.append(ref_entry)

                # handle storing bitwarden style
                username_and_password_match = True
                kp_username = kp_entry.username or ""
                kp_password = kp_entry.password or ""
                for ref_entry in replaced_entries:
                    if (
                        ref_entry["login"]["username"] != kp_username
                        or ref_entry["login"]["password"] != kp_password
                    ):
                        username_and_password_match = False
                        break

                if username_and_password_match and ref_entry is not None:
                    # => add url to bw_item => username / pw identical
                    if kp_entry.url:
                        ref_entry["login"]["uris"].append(
                            BwUri(uri=kp_entry.url, match=None)
                        )
                else:
                    # => create new bitwarden item
                    self._add_bw_entry_to_entries_dict(kp_entry, None)

            except ConversionError, KeyError, AttributeError:
                group = kp_entry.group
                group_path = group.path if group is not None else []
                logger.warning(
                    f"!! Could not resolve entry for {group_path}{kp_entry.title} [{kp_entry.uuid!s}] !!"
                )

        logger.log(VERBOSE, f"Resolved {ref_entries_length} REF entries")

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
        firstlevel: str | None,
    ) -> str | None:
        """Resolve and set collection ID on *bw_item*."""
        collection_id: str | None = None
        if self._bitwarden_coll_id == "auto":
            if firstlevel:
                logger.log(VERBOSE, f"Searching Collection {firstlevel}")
                collection_id = bw.create_org_collection(firstlevel)
        elif self._bitwarden_coll_id:
            collection_id = self._bitwarden_coll_id

        if collection_id is not None:
            # Intentional in-place mutation: _entries is reset by
            # _load_keepass_data() before each convert() run, so mutating
            # bw_item here is safe for the current single-pass architecture.
            bw_item["collectionIds"] = [collection_id]
        return collection_id

    @staticmethod
    def _attachment_filename(att: AttachmentItem) -> str:
        """Return the Bitwarden filename an AttachmentItem materialises to.

        Single source of truth for the naming rule, shared by
        :meth:`_materialise_attachment` (which uploads) and upload-if-missing
        reconciliation (which compares names without encoding the payload), so
        the two can never drift apart.
        """
        if not isinstance(att, Attachment):
            # Long custom property — (key, value) text tuple
            return att[0] + ".txt"
        # Real pykeepass Attachment
        return att.filename if att.filename else "attachment"

    @staticmethod
    def _materialise_attachment(att: AttachmentItem) -> tuple[str, bytes]:
        """Convert an AttachmentItem to a ``(filename, data)`` pair."""
        name = Converter._attachment_filename(att)
        if isinstance(att, Attachment):
            return name, att.data
        return name, att[1].encode("UTF-8")

    @staticmethod
    def _fields_signature(
        fields: list[BwField] | None,
    ) -> list[tuple[str, str, int]]:
        """Order-independent (name, value, type) signature of custom fields."""
        return sorted(
            (
                (f.get("name") or "", f.get("value") or "", f.get("type") or 0)
                for f in (fields or [])
            ),
            key=lambda t: (t[0], t[2], t[1]),
        )

    @staticmethod
    def _login_differs(existing: BwItemLogin | None, desired: BwItemLogin) -> bool:
        """Compare the login fields kp2bw owns (creds, totp, URIs)."""
        if existing is None:
            existing = BwItemLogin(
                uris=[],
                username="",
                password="",
                totp=None,
                passwordRevisionDate=None,
            )
        if (existing.get("username") or "") != (desired.get("username") or ""):
            return True
        if (existing.get("password") or "") != (desired.get("password") or ""):
            return True
        if (existing.get("totp") or "") != (desired.get("totp") or ""):
            return True
        ex_uris = [u.get("uri", "") for u in (existing.get("uris") or [])]
        de_uris = [u.get("uri", "") for u in (desired.get("uris") or [])]
        return ex_uris != de_uris

    @classmethod
    def _content_differs(cls, existing: BwItemResponse, desired: BwItemCreate) -> bool:
        """True if the KeePass-derived content diverges from the vault item.

        Compares only the fields kp2bw manages (name, notes, custom fields and
        the login credentials/URIs) so an unchanged re-run stays idempotent and
        never issues a redundant PUT.
        """
        if (existing.get("name") or "") != (desired.get("name") or ""):
            return True
        if (existing.get("notes") or "") != (desired.get("notes") or ""):
            return True
        if cls._fields_signature(existing.get("fields")) != cls._fields_signature(
            desired.get("fields")
        ):
            return True
        return cls._login_differs(existing.get("login"), desired["login"])

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
        payload: BwItemResponse = copy.copy(existing)
        payload["name"] = desired["name"]
        payload["notes"] = desired["notes"]
        payload["fields"] = desired["fields"]

        desired_login: BwItemLogin = copy.copy(desired["login"])
        ex_login = existing.get("login")
        if "fido2Credentials" not in desired_login and ex_login:
            ex_fido2 = ex_login.get("fido2Credentials")
            if ex_fido2:
                desired_login["fido2Credentials"] = ex_fido2
        payload["login"] = desired_login

        target_colls = desired.get("collectionIds") or []
        existing_colls = existing.get("collectionIds") or []
        missing = [c for c in target_colls if c not in existing_colls]
        payload["collectionIds"] = existing_colls + missing
        return payload

    @staticmethod
    def _existing_attachment_names(
        bw: BitwardenServeClient, item_id: str
    ) -> set[str] | None:
        """Return filenames already attached to *item_id*, or ``None`` on error.

        Fetched authoritatively via GET so upload-if-missing never duplicates a
        file.  ``None`` signals "could not determine" so the caller skips the
        upload rather than risk a duplicate.
        """
        try:
            item = bw.get_item(item_id)
        except BitwardenClientError:
            logger.warning(
                f"Could not read existing attachments for item {item_id}; "
                f"skipping its attachment sync to avoid duplicates"
            )
            return None
        return {
            a.get("fileName", "")
            for a in (item.get("attachments") or [])
            if a.get("fileName")
        }

    def _reconcile_existing_item(
        self,
        bw: BitwardenServeClient,
        existing: BwItemResponse,
        folder: str | None,
        bw_item: BwItemCreate,
        attachments: list[AttachmentItem],
        *,
        fixed_coll_id: str | None,
    ) -> tuple[
        Literal["updated", "collection", "skipped", "failed"], list[AttachmentItem]
    ]:
        """Sync KeePass changes onto an item that already exists in the vault.

        Returns ``(outcome, missing_attachments)`` where *outcome* is one of
        ``"updated"`` (content PUT), ``"collection"`` (membership-only PUT),
        ``"skipped"`` (no change) or ``"failed"`` (the PUT was rejected), and
        *missing_attachments* are the files the item does not yet have and that
        should be uploaded.
        """
        name = bw_item["name"]
        item_id = existing["id"]
        outcome: Literal["updated", "collection", "skipped", "failed"] = "skipped"

        # Content/collection sync. A rejected PUT here is non-fatal: one
        # problematic entry must not abort the whole re-run and strand every
        # entry after it (the same robustness the attachment phase has).
        try:
            # Content sync: PUT only login-type items we own, and only when the
            # KeePass-derived content changed (keeps re-runs idempotent).
            if (
                self._update_existing
                and existing.get("type") == BW_ITEM_TYPE_LOGIN
                and self._content_differs(existing, bw_item)
            ):
                payload = self._build_update_payload(existing, bw_item)
                bw.update_item(item_id, payload)
                bw.update_dedup_entry(folder, name, payload)
                logger.log(VERBOSE, f"-- Entry {name!r}: content updated from KeePass")
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
                    # Keep the cache fresh so a second KeePass entry with the
                    # same (folder, name) doesn't recompute stale collectionIds.
                    bw.update_dedup_entry(folder, name, updated_item)
                    logger.log(
                        VERBOSE,
                        f"-- Entry {name!r}: added to {len(missing)} collection(s)",
                    )
                    outcome = "collection"
        except BitwardenClientError as exc:
            logger.warning(
                f"-- Entry {name!r}: update failed, leaving the existing "
                f"item unchanged: {exc}"
            )
            outcome = "failed"

        # Attachment sync: upload only files the item is missing, so a
        # previously-skipped entry finally gets its notes.txt / long-field / file
        # attachments without ever duplicating ones already present.
        missing_atts: list[AttachmentItem] = []
        if self._update_existing and attachments:
            existing_names = self._existing_attachment_names(bw, item_id)
            if existing_names is not None:
                missing_atts = [
                    att
                    for att in attachments
                    if self._attachment_filename(att) not in existing_names
                ]

        if outcome == "skipped" and not missing_atts:
            logger.log(
                VERBOSE,
                f"-- Entry {name!r} unchanged in folder {folder!r}, skipping",
            )

        return outcome, missing_atts

    def _create_bitwarden_items_for_entries(self) -> int:
        """Create entries via ``bw serve`` HTTP API and upload attachments.

        Returns the count of non-fatal failures (rejected updates + uploads).
        """
        logger.info("Connecting and reading existing folders and entries")

        # When a fixed collection ID is given, scope the dedup index to that
        # collection so items that exist in *other* collections are treated as
        # new and are imported into the target collection rather than skipped.
        fixed_coll_id = (
            self._bitwarden_coll_id
            if self._bitwarden_coll_id and self._bitwarden_coll_id != "auto"
            else None
        )

        n_skipped = 0
        n_updated = 0
        n_collection_update = 0
        n_created = 0
        n_attachments = 0
        n_attach_failed = 0
        n_update_failed = 0
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
            BitwardenServeClient(
                self._bitwarden_password,
                org_id=self._bitwarden_organization_id,
                collection_id=fixed_coll_id,
            ) as bw,
        ):
            # --- Phase 1: Partition entries and resolve collections ----------
            import_entries: dict[str, tuple[str | None, BwItemCreate]] = {}
            attachment_map: dict[str, list[AttachmentItem]] = {}
            # Existing items needing only missing attachments uploaded:
            # (item_id, [attachments]).
            existing_uploads: list[tuple[str, list[AttachmentItem]]] = []
            # Vault items already reconciled this run, so two KeePass entries
            # sharing one (folder, name) don't double-PUT or double-upload.
            reconciled_ids: set[str] = set()

            task1 = progress.add_task("Processing entries", total=len(self._entries))
            for key, entry_value in self._entries.items():
                folder, firstlevel, bw_item, attachments = self._unpack_entry(
                    entry_value
                )

                # Resolve collection (mutates bw_item)
                self._resolve_collection(bw, bw_item, firstlevel)

                # An item with this (folder, name) already exists: sync any
                # KeePass changes onto it (content, collection membership, and
                # missing attachments) instead of blindly skipping it.
                existing = bw.get_existing_item(folder, bw_item["name"])
                if existing is not None:
                    # Two KeePass entries can map to the same vault item (same
                    # folder + title); reconcile it once to avoid a redundant
                    # PUT and a duplicate attachment upload.
                    if existing["id"] in reconciled_ids:
                        n_skipped += 1
                        progress.advance(task1)
                        continue
                    reconciled_ids.add(existing["id"])

                    outcome, missing_atts = self._reconcile_existing_item(
                        bw,
                        existing,
                        folder,
                        bw_item,
                        attachments,
                        fixed_coll_id=fixed_coll_id,
                    )
                    if outcome == "updated":
                        n_updated += 1
                    elif outcome == "collection":
                        n_collection_update += 1
                    elif outcome == "failed":
                        n_update_failed += 1
                    else:  # "skipped" — content unchanged (attachments, if any,
                        # are reported separately via the attachment counters).
                        n_skipped += 1
                    if missing_atts:
                        existing_uploads.append((existing["id"], missing_atts))
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

                key_to_id = bw.create_items_batch(
                    import_entries, on_item_created=_on_created
                )
            else:
                key_to_id = {}

            # --- Phase 3: Parallel attachment uploads -----------------------
            # Newly-created items (resolve their server-assigned IDs) and
            # existing items missing attachments share one upload pass.
            upload_items: list[tuple[str, list[tuple[str, bytes]]]] = []
            for key, new_atts in attachment_map.items():
                item_id = key_to_id.get(key)
                if not item_id:
                    _folder, miss_item = import_entries[key]
                    logger.warning(
                        f"Could not find item ID for {miss_item['name']!r} "
                        f"in folder {_folder!r} for attachment upload"
                    )
                    continue
                upload_items.append((
                    item_id,
                    [self._materialise_attachment(a) for a in new_atts],
                ))
            for item_id, existing_atts in existing_uploads:
                upload_items.append((
                    item_id,
                    [self._materialise_attachment(a) for a in existing_atts],
                ))

            if upload_items:
                total_files = sum(len(fps) for _, fps in upload_items)
                task3 = progress.add_task(
                    "Uploading attachments", total=len(upload_items)
                )
                failed = bw.upload_attachments(upload_items)
                n_attach_failed = len(failed)
                n_attachments = total_files - n_attach_failed
                progress.update(task3, completed=len(upload_items))

        elapsed = time.monotonic() - t_start
        _print_summary(
            elapsed,
            n_created,
            n_updated,
            n_skipped,
            n_collection_update,
            n_attachments,
            n_update_failed,
            n_attach_failed,
        )
        return n_update_failed + n_attach_failed

    def convert(self) -> int:
        """Run the full KeePass-to-Bitwarden migration pipeline.

        Returns the number of non-fatal failures (rejected entry updates plus
        rejected attachment uploads); ``0`` means everything succeeded.
        """
        # load keepass data from database
        self._load_keepass_data()

        # resolve {REF:...} stuff
        self._resolve_entries_with_references()

        # store aggregated entries in bw
        return self._create_bitwarden_items_for_entries()
