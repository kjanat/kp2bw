import uuid as _uuid
from datetime import datetime
from io import IOBase
from logging import Logger
from pathlib import Path
from typing import Any, Final, Literal, Self, TypeAlias, overload

from construct import Container
from lxml.etree import Element, ElementTree
from pykeepass.attachment import Attachment
from pykeepass.entry import Entry
from pykeepass.group import Group

_CastResult: TypeAlias = Entry | Group | Attachment

logger: Logger
BLANK_DATABASE_FILENAME: Final[str]
BLANK_DATABASE_LOCATION: Final[str]
BLANK_DATABASE_PASSWORD: Final[str]

class PyKeePass:
    filename: str | Path
    kdbx: Container

    def __init__(
        self,
        filename: str | Path | IOBase,
        password: str | None = None,
        keyfile: str | Path | None = None,
        transformed_key: bytes | None = None,
        decrypt: bool = True,
    ) -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        typ: type[BaseException] | None,
        value: BaseException | None,
        tb: object,
    ) -> None: ...
    def read(
        self,
        filename: str | Path | IOBase | None = None,
        password: str | None = None,
        keyfile: str | Path | None = None,
        transformed_key: bytes | None = None,
        decrypt: bool = True,
    ) -> None: ...
    def reload(self) -> None: ...
    def save(
        self,
        filename: str | Path | IOBase | None = None,
        transformed_key: bytes | None = None,
    ) -> None: ...
    @property
    def version(self) -> tuple[int, int]: ...
    @property
    def encryption_algorithm(self) -> str: ...
    @property
    def kdf_algorithm(self) -> str | None: ...
    @property
    def transformed_key(self) -> bytes: ...
    @property
    def database_salt(self) -> bytes: ...
    @property
    def payload(self) -> Container: ...
    @property
    def tree(self) -> ElementTree: ...
    @property
    def root_group(self) -> Group: ...
    @property
    def recyclebin_group(self) -> Group | None: ...
    @property
    def groups(self) -> list[Group]: ...
    @property
    def entries(self) -> list[Entry]: ...
    @property
    def database_name(self) -> str | None: ...
    @database_name.setter
    def database_name(self, name: str) -> None: ...
    @property
    def database_description(self) -> str | None: ...
    @database_description.setter
    def database_description(self, name: str) -> None: ...
    @property
    def default_username(self) -> str | None: ...
    @default_username.setter
    def default_username(self, name: str) -> None: ...
    def xml(self) -> bytes: ...
    def dump_xml(self, filename: str) -> None: ...
    @overload
    def xpath(
        self,
        xpath_str: str,
        tree: Element | ElementTree | None = None,
        first: Literal[False] = False,
        cast: Literal[False] = False,
        **kwargs: Any,
    ) -> list[Element]: ...
    @overload
    def xpath(
        self,
        xpath_str: str,
        tree: Element | ElementTree | None = None,
        first: Literal[True] = ...,
        cast: Literal[False] = False,
        **kwargs: Any,
    ) -> Element | None: ...
    @overload
    def xpath(
        self,
        xpath_str: str,
        tree: Element | ElementTree | None = None,
        first: Literal[False] = False,
        cast: Literal[True] = ...,
        **kwargs: Any,
    ) -> list[_CastResult]: ...
    @overload
    def xpath(
        self,
        xpath_str: str,
        tree: Element | ElementTree | None = None,
        first: Literal[True] = ...,
        cast: Literal[True] = ...,
        **kwargs: Any,
    ) -> _CastResult | None: ...

    _xpath = xpath

    def _find(
        self,
        prefix: str,
        keys_xp: dict[bool, dict[str, str]],
        path: list[str | None] | None = None,
        tree: Entry | Group | None = None,
        first: bool = False,
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
        **kwargs: Any,
    ) -> list[_CastResult] | _CastResult | None: ...
    def _can_be_moved_to_recyclebin(self, entry_or_group: Entry | Group) -> bool: ...
    def _create_or_get_recyclebin_group(
        self, group_name: str = ..., icon: str | None = ..., notes: str | None = ...
    ) -> Group: ...

    # --- Groups ---

    @overload
    def find_groups(
        self,
        *,
        path: list[str],
        recursive: bool = True,
        group: Group | None = None,
        first: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> Group | None: ...
    @overload
    def find_groups(
        self,
        recursive: bool,
        path: list[str],
        group: Group | None = None,
        *,
        first: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> Group | None: ...
    @overload
    def find_groups(
        self,
        recursive: bool = True,
        path: None = None,
        group: Group | None = None,
        *,
        name: str | None = None,
        uuid: _uuid.UUID | None = None,
        notes: str | None = None,
        first: Literal[True],
        regex: bool = False,
        flags: str | None = None,
    ) -> Group | None: ...
    @overload
    def find_groups(
        self,
        recursive: bool = True,
        path: None = None,
        group: Group | None = None,
        *,
        name: str | None = None,
        uuid: _uuid.UUID | None = None,
        notes: str | None = None,
        first: Literal[False] = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> list[Group]: ...
    @overload
    def find_groups_by_name(
        self,
        group_name: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        first: Literal[False] = False,
    ) -> list[Group]: ...
    @overload
    def find_groups_by_name(
        self,
        group_name: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        first: Literal[True] = ...,
    ) -> Group | None: ...
    @overload
    def find_groups_by_path(
        self,
        group_path_str: list[str],
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        first: bool = False,
    ) -> Group | None: ...
    @overload
    def find_groups_by_path(
        self,
        group_path_str: None = None,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        first: Literal[False] = False,
    ) -> list[Group]: ...
    @overload
    def find_groups_by_path(
        self,
        group_path_str: None = None,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        first: Literal[True] = ...,
    ) -> Group | None: ...
    @overload
    def find_groups_by_uuid(
        self,
        uuid: _uuid.UUID,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Group]: ...
    @overload
    def find_groups_by_uuid(
        self,
        uuid: _uuid.UUID,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Group | None: ...
    @overload
    def find_groups_by_notes(
        self,
        notes: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Group]: ...
    @overload
    def find_groups_by_notes(
        self,
        notes: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Group | None: ...
    def add_group(
        self,
        destination_group: Group,
        group_name: str,
        icon: str | None = None,
        notes: str | None = None,
    ) -> Group: ...
    def delete_group(self, group: Group) -> None: ...
    def move_group(self, group: Group, destination_group: Group) -> None: ...
    def trash_group(self, group: Group) -> None: ...
    def empty_group(self, group: Group) -> None: ...

    # --- Entries ---

    @overload
    def find_entries(
        self,
        *,
        path: list[str | None],
        recursive: bool = True,
        group: Group | None = None,
        first: bool = False,
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> Entry | None: ...
    @overload
    def find_entries(
        self,
        recursive: bool,
        path: list[str | None],
        group: Group | None = None,
        *,
        first: bool = False,
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> Entry | None: ...
    @overload
    def find_entries(
        self,
        recursive: bool = True,
        path: None = None,
        group: Group | None = None,
        *,
        title: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        otp: str | None = None,
        string: dict[str, str] | None = None,
        uuid: _uuid.UUID | None = None,
        tags: list[str] | None = None,
        autotype_enabled: bool | None = None,
        autotype_sequence: str | None = None,
        autotype_window: str | None = None,
        first: Literal[True],
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> Entry | None: ...
    @overload
    def find_entries(
        self,
        recursive: bool = True,
        path: None = None,
        group: Group | None = None,
        *,
        title: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        otp: str | None = None,
        string: dict[str, str] | None = None,
        uuid: _uuid.UUID | None = None,
        tags: list[str] | None = None,
        autotype_enabled: bool | None = None,
        autotype_sequence: str | None = None,
        autotype_window: str | None = None,
        first: Literal[False] = False,
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> list[Entry]: ...
    @overload
    def find_entries_by_title(
        self,
        title: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Entry]: ...
    @overload
    def find_entries_by_title(
        self,
        title: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Entry | None: ...
    @overload
    def find_entries_by_username(
        self,
        username: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Entry]: ...
    @overload
    def find_entries_by_username(
        self,
        username: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Entry | None: ...
    @overload
    def find_entries_by_password(
        self,
        password: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Entry]: ...
    @overload
    def find_entries_by_password(
        self,
        password: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Entry | None: ...
    @overload
    def find_entries_by_url(
        self,
        url: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Entry]: ...
    @overload
    def find_entries_by_url(
        self,
        url: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Entry | None: ...
    @overload
    def find_entries_by_notes(
        self,
        notes: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Entry]: ...
    @overload
    def find_entries_by_notes(
        self,
        notes: str,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Entry | None: ...
    @overload
    def find_entries_by_path(
        self,
        path: list[str | None],
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: bool = False,
    ) -> Entry | None: ...
    @overload
    def find_entries_by_path(
        self,
        path: None = None,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Entry]: ...
    @overload
    def find_entries_by_path(
        self,
        path: None = None,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Entry | None: ...
    @overload
    def find_entries_by_uuid(
        self,
        uuid: _uuid.UUID,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Entry]: ...
    @overload
    def find_entries_by_uuid(
        self,
        uuid: _uuid.UUID,
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Entry | None: ...
    @overload
    def find_entries_by_string(
        self,
        string: dict[str, str],
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[False] = False,
    ) -> list[Entry]: ...
    @overload
    def find_entries_by_string(
        self,
        string: dict[str, str],
        regex: bool = False,
        flags: str | None = None,
        group: Group | None = None,
        history: bool = False,
        first: Literal[True] = ...,
    ) -> Entry | None: ...
    def add_entry(
        self,
        destination_group: Group,
        title: str | None,
        username: str | None,
        password: str | None,
        url: str | None = None,
        notes: str | None = None,
        expiry_time: datetime | None = None,
        tags: list[str] | str | None = None,
        otp: str | None = None,
        icon: str | None = None,
        force_creation: bool = False,
    ) -> Entry: ...
    def delete_entry(self, entry: Entry) -> None: ...
    def move_entry(self, entry: Entry, destination_group: Group) -> None: ...
    def trash_entry(self, entry: Entry) -> None: ...

    # --- Attachments ---

    @overload
    def find_attachments(
        self,
        *,
        path: list[str | None],
        recursive: bool = True,
        element: Entry | Group | None = None,
        first: bool = False,
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> Attachment | None: ...
    @overload
    def find_attachments(
        self,
        recursive: bool,
        path: list[str | None],
        element: Entry | Group | None = None,
        *,
        first: bool = False,
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> Attachment | None: ...
    @overload
    def find_attachments(
        self,
        recursive: bool = True,
        path: None = None,
        element: Entry | Group | None = None,
        *,
        id: int | None = None,
        filename: str | None = None,
        first: Literal[True],
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> Attachment | None: ...
    @overload
    def find_attachments(
        self,
        recursive: bool = True,
        path: None = None,
        element: Entry | Group | None = None,
        *,
        id: int | None = None,
        filename: str | None = None,
        first: Literal[False] = False,
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> list[Attachment]: ...
    @property
    def attachments(self) -> list[Attachment]: ...
    @property
    def binaries(self) -> list[bytes]: ...
    def add_binary(
        self, data: bytes, compressed: bool = True, protected: bool = True
    ) -> int: ...
    def delete_binary(self, id: int) -> None: ...

    # --- Misc ---

    def deref(self, value: str | None) -> str | None: ...
    def _encode_time(self, value: datetime) -> str: ...
    def _decode_time(self, text: str) -> datetime: ...

    # --- Credentials ---

    @property
    def password(self) -> str | None: ...
    @password.setter
    def password(self, password: str | None) -> None: ...
    @property
    def keyfile(self) -> str | Path | None: ...
    @keyfile.setter
    def keyfile(self, keyfile: str | Path | None) -> None: ...
    @property
    def credchange_required_days(self) -> int | None: ...
    @credchange_required_days.setter
    def credchange_required_days(self, days: int) -> None: ...
    @property
    def credchange_recommended_days(self) -> int | None: ...
    @credchange_recommended_days.setter
    def credchange_recommended_days(self, days: int) -> None: ...
    @property
    def credchange_date(self) -> datetime | None: ...
    @credchange_date.setter
    def credchange_date(self, date: datetime) -> None: ...
    @property
    def credchange_required(self) -> bool: ...
    @property
    def credchange_recommended(self) -> bool: ...

def create_database(
    filename: str | Path | IOBase,
    password: str | None = None,
    keyfile: str | Path | None = None,
    transformed_key: bytes | None = None,
) -> PyKeePass: ...
def debug_setup() -> None: ...
