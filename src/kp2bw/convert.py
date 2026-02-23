import base64
import binascii
import logging
from itertools import islice
from typing import Any

from pykeepass import Attachment, Entry, Group, PyKeePass

from .bw_serve import BitwardenServeClient
from .exceptions import ConversionError

logger = logging.getLogger(__name__)

KP_REF_IDENTIFIER: str = "{REF:"
MAX_BW_ITEM_LENGTH: int = 10 * 1000
KPEX_PASSKEY_PREFIX: str = "KPEX_PASSKEY_"

# Bitwarden item dict type
type BwItem = dict[str, Any]

# Attachment-like: real pykeepass Attachment or (key, value) tuple for long fields
type AttachmentItem = Attachment | tuple[str, str]

# Entry storage: 2-tuple (folder, bw_item) or 3-tuple (folder, bw_item, attachments)
type EntryValue = (
    tuple[str | None, BwItem] | tuple[str | None, BwItem, list[AttachmentItem]]
)

# Fido2 credential list type
type Fido2Credentials = list[dict[str, str | None]]


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

    def _build_fido2_credentials(self, entry: Entry) -> Fido2Credentials | None:
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

        return [
            {
                "credentialId": credential_id,
                "keyType": "public-key",
                "keyAlgorithm": "ECDSA",
                "keyCurve": "P-256",
                "keyValue": key_value,
                "rpId": props.get("KPEX_PASSKEY_RELYING_PARTY", ""),
                "rpName": props.get("KPEX_PASSKEY_RELYING_PARTY", ""),
                "userHandle": props.get("KPEX_PASSKEY_USER_HANDLE", ""),
                "userName": props.get("KPEX_PASSKEY_USERNAME", entry.username or ""),
                "userDisplayName": props.get(
                    "KPEX_PASSKEY_USERNAME", entry.username or ""
                ),
                "counter": "0",
                "discoverable": "true",
                "creationDate": creation_date,
            }
        ]

    def _create_bw_python_object(
        self,
        title: str,
        notes: str,
        url: str,
        totp: str,
        username: str,
        password: str,
        custom_properties: dict[str, list[Any]],
        collection_id: str | None,
        firstlevel: str | None,
        fido2_credentials: Fido2Credentials | None = None,
    ) -> BwItem:
        """Build a Bitwarden item dict from individual entry fields."""
        login: dict[str, Any] = {
            "uris": [{"match": None, "uri": url}] if url else [],
            "username": username,
            "password": password,
            "totp": totp,
            "passwordRevisionDate": None,
        }
        if fido2_credentials:
            login["fido2Credentials"] = fido2_credentials

        return {
            "organizationId": self._bitwarden_organization_id,
            "collectionIds": collection_id,
            "firstlevel": firstlevel,
            "folderId": None,
            "type": 1,
            "name": title,
            "notes": notes,
            "favorite": False,
            "fields": [
                {"name": key, "value": value[0], "type": value[1]}
                for key, value in custom_properties.items()
                if value[0] is not None and len(value[0]) <= MAX_BW_ITEM_LENGTH
            ],
            "login": login,
            "secureNote": None,
            "card": None,
            "identity": None,
        }

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

    def _build_metadata_fields(self, entry: Entry) -> dict[str, list[Any]]:
        """Build extra custom fields for KeePass metadata (tags, expiry, timestamps)."""
        fields: dict[str, list[Any]] = {}

        # Tags
        if entry.tags:
            fields["KeePass Tags"] = [", ".join(entry.tags), 0]

        # Expiry
        if entry.expires and entry.expiry_time:
            fields["Expires"] = [entry.expiry_time.isoformat(), 0]

        # Timestamps
        if entry.ctime:
            fields["Created"] = [entry.ctime.isoformat(), 0]
        if entry.mtime:
            fields["Modified"] = [entry.mtime.isoformat(), 0]

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

        custom_properties: dict[str, list[Any]] = {}
        for key, value in entry.custom_properties.items():
            # Skip KeePassXC passkey attributes -- handled separately
            if key.startswith(KPEX_PASSKEY_PREFIX):
                continue
            if key in custom_protected:
                custom_properties[key] = [value, 1]
            else:
                custom_properties[key] = [value, 0]

        # Add metadata fields (tags, expiry, timestamps) if enabled
        if self._migrate_metadata:
            custom_properties.update(self._build_metadata_fields(entry))

        # Build FIDO2/passkey credentials from KeePassXC attributes
        fido2_credentials = self._build_fido2_credentials(entry)
        if fido2_credentials:
            logger.info(f"  Migrating passkey for entry: {entry.title}")

        # Build notes, prepending [EXPIRED] marker if applicable
        notes = ""
        if entry.notes and len(entry.notes) <= MAX_BW_ITEM_LENGTH:
            notes = entry.notes
        if entry.expired:
            expired_prefix = "[EXPIRED] "
            notes = expired_prefix + notes

        title: str = prefix + entry.title if entry.title else prefix + "_untitled"
        bw_item_object = self._create_bw_python_object(
            title=title,
            notes=notes,
            url=entry.url if entry.url else "",
            totp=entry.otp if entry.otp else "",
            username=entry.username if entry.username else "",
            password=entry.password if entry.password else "",
            custom_properties=custom_properties,
            collection_id=self._bitwarden_coll_id,
            firstlevel=self._get_folder_firstlevel(entry),
            fido2_credentials=fido2_credentials,
        )

        # get attachments to store later on
        attachments: list[AttachmentItem] = [
            (key, value)
            for key, value in entry.custom_properties.items()
            if value is not None and len(value) > MAX_BW_ITEM_LENGTH
        ]

        if entry.notes and len(entry.notes) > MAX_BW_ITEM_LENGTH:
            attachments.append(("notes", entry.notes))

        entry_key: str = str(entry.uuid).replace("-", "").upper()
        if entry.attachments or attachments:
            attachments += entry.attachments
            self._entries[entry_key] = (
                folder,
                bw_item_object,
                attachments,
            )
        else:
            self._entries[entry_key] = (
                folder,
                bw_item_object,
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
        self, ref_entry: BwItem, field_referenced: str
    ) -> str | None:
        """Extract the referenced login field (username/password) from a resolved entry."""
        for member, reference_key in self._member_reference_resolving_dict.items():
            if field_referenced == reference_key:
                return ref_entry["login"][member]

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
                logger.debug(f"Skipping expired entry: {entry.title}")
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
                replaced_entries: list[BwItem] = []
                ref_entry: BwItem | None = None
                for member in self._member_reference_resolving_dict:
                    if KP_REF_IDENTIFIER in getattr(kp_entry, member):
                        field_referenced, lookup_mode, ref_compare_string = (
                            self._parse_kp_ref_string(getattr(kp_entry, member))
                        )
                        ref_result = self._get_referenced_entry(
                            lookup_mode, ref_compare_string
                        )
                        ref_entry = ref_result[1]

                        value = self._find_referenced_value(ref_entry, field_referenced)
                        setattr(kp_entry, member, value)

                        replaced_entries.append(ref_entry)

                # handle storing bitwarden style
                username_and_password_match = True
                for ref_entry in replaced_entries:
                    if (
                        ref_entry["login"]["username"] != kp_entry.username
                        or ref_entry["login"]["password"] != kp_entry.password
                    ):
                        username_and_password_match = False
                        break

                if username_and_password_match and ref_entry is not None:
                    # => add url to bw_item => username / pw identical
                    ref_entry["login"]["uris"].append({
                        "match": None,
                        "uri": kp_entry.url,
                    })
                else:
                    # => create new bitwarden item
                    self._add_bw_entry_to_entries_dict(kp_entry, None)

            except ConversionError, KeyError, AttributeError:
                group = kp_entry.group
                group_path = group.path if group is not None else []
                logger.warning(
                    f"!! Could not resolve entry for {group_path}{kp_entry.title} [{kp_entry.uuid!s}] !!"
                )

        logger.debug(f"Resolved {ref_entries_length} REF entries")

    @staticmethod
    def _unpack_entry(
        entry_value: EntryValue,
    ) -> tuple[str | None, BwItem, list[AttachmentItem] | None]:
        """Destructure an entry value into (folder, item, attachments)."""
        if len(entry_value) == 2:
            return entry_value[0], entry_value[1], None
        folder = entry_value[0]
        bw_item = entry_value[1]
        attachments: list[AttachmentItem] = entry_value[2]  # type: ignore[index]
        return folder, bw_item, attachments

    def _resolve_collection(
        self, bw: BitwardenServeClient, bw_item: BwItem
    ) -> str | None:
        """Resolve and set collection ID on *bw_item*, strip ``firstlevel``."""
        collection_id: str | None = None
        firstlevel = bw_item.get("firstlevel")
        if firstlevel:
            if self._bitwarden_coll_id == "auto":
                logger.info(f"Searching Collection {firstlevel}")
                collection_id = bw.create_org_collection(firstlevel)
            elif self._bitwarden_coll_id:
                collection_id = self._bitwarden_coll_id
        bw_item.pop("firstlevel", None)
        bw_item["collectionIds"] = collection_id
        return collection_id

    @staticmethod
    def _materialise_attachment(att: AttachmentItem) -> tuple[str, bytes]:
        """Convert an AttachmentItem to a ``(filename, data)`` pair."""
        if not isinstance(att, Attachment):
            # Long custom property — (key, value) text tuple
            name: str = att[0]
            value: str = att[1]
            return name + ".txt", value.encode("UTF-8")
        # Real pykeepass Attachment
        filename = att.filename if att.filename else "attachment"
        data: bytes = att.data
        return filename, data

    def _create_bitwarden_items_for_entries(self) -> None:
        """Create entries via ``bw serve`` HTTP API and upload attachments."""
        logger.info("Connecting and reading existing folders and entries")

        with BitwardenServeClient(
            self._bitwarden_password,
            org_id=self._bitwarden_organization_id,
        ) as bw:
            # --- Phase 1: Partition entries and resolve collections ----------
            import_entries: dict[str, tuple[str | None, BwItem]] = {}
            attachment_map: dict[str, list[AttachmentItem]] = {}

            for key, entry_value in self._entries.items():
                folder, bw_item, attachments = self._unpack_entry(entry_value)

                # Resolve collection (mutates bw_item)
                self._resolve_collection(bw, bw_item)

                # Dedup check
                if bw.entry_exists(folder, bw_item["name"]):
                    logger.info(
                        f"-- Entry {bw_item['name']} already exists in "
                        f"folder {folder}. skipping..."
                    )
                    continue

                import_entries[key] = (folder, bw_item)
                if attachments:
                    attachment_map[key] = attachments

            if not import_entries:
                logger.info("No new entries to import")
                return

            # --- Phase 2: Create items via bw serve HTTP API ----------------
            logger.info(f"Creating {len(import_entries)} items via bw serve HTTP API")
            key_to_id = bw.create_items_batch(import_entries)
            logger.info(f"Created {len(key_to_id)} items")

            if not attachment_map:
                logger.info("No attachments to upload")
                return

            # --- Phase 3: Parallel attachment uploads -----------------------
            upload_items: list[tuple[str, list[tuple[str, bytes]]]] = []
            for key, attachments in attachment_map.items():
                item_id = key_to_id.get(key)
                if not item_id:
                    folder, bw_item = import_entries[key]
                    logger.warning(
                        f"Could not find item ID for {bw_item['name']!r} "
                        f"in folder {folder!r} for attachment upload"
                    )
                    continue

                file_pairs = [self._materialise_attachment(att) for att in attachments]
                upload_items.append((item_id, file_pairs))

            bw.upload_attachments(upload_items)

    def convert(self) -> None:
        """Run the full KeePass-to-Bitwarden migration pipeline."""
        # load keepass data from database
        self._load_keepass_data()

        # resolve {REF:...} stuff
        self._resolve_entries_with_references()

        # store aggregated entries in bw
        self._create_bitwarden_items_for_entries()
