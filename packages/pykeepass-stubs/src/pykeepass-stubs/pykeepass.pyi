import uuid as _uuid
from datetime import datetime
from io import IOBase
from pathlib import Path
from typing import Any, Self, overload

from lxml.etree import Element, ElementTree
from pykeepass.attachment import Attachment
from pykeepass.entry import Entry
from pykeepass.group import Group

class PyKeePass:
    filename: str | Path
    kdbx: object

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
        *,
        first: bool = False,
        cast: bool = False,
        **kwargs: Any,
    ) -> list[Element]: ...
    @overload
    def xpath(
        self,
        xpath_str: str,
        tree: Element | ElementTree | None = None,
        first: bool = False,
        cast: bool = False,
        **kwargs: Any,
    ) -> list[Element] | Element | None: ...
    def xpath(
        self,
        xpath_str: str,
        tree: Element | ElementTree | None = None,
        first: bool = False,
        cast: bool = False,
        **kwargs: Any,
    ) -> list[Element] | Element | None: ...

    _xpath = xpath

    # --- Groups ---

    def find_groups(
        self,
        recursive: bool = True,
        path: list[str] | None = None,
        group: Group | None = None,
        *,
        name: str | None = None,
        uuid: _uuid.UUID | None = None,
        notes: str | None = None,
        first: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> list[Group] | Group | None: ...
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

    def find_entries(
        self,
        recursive: bool = True,
        path: list[str | None] | None = None,
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
        first: bool = False,
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> list[Entry] | Entry | None: ...
    def add_entry(
        self,
        destination_group: Group,
        title: str | None,
        username: str | None,
        password: str | None,
        url: str | None = None,
        notes: str | None = None,
        expiry_time: datetime | None = None,
        tags: list[str] | None = None,
        otp: str | None = None,
        icon: str | None = None,
        force_creation: bool = False,
    ) -> Entry: ...
    def delete_entry(self, entry: Entry) -> None: ...
    def move_entry(self, entry: Entry, destination_group: Group) -> None: ...
    def trash_entry(self, entry: Entry) -> None: ...

    # --- Attachments ---

    def find_attachments(
        self,
        recursive: bool = True,
        path: list[str] | None = None,
        element: Entry | Group | None = None,
        *,
        id: int | None = None,
        filename: str | None = None,
        first: bool = False,
        history: bool = False,
        regex: bool = False,
        flags: str | None = None,
    ) -> list[Attachment] | Attachment | None: ...
    @property
    def attachments(self) -> list[Attachment]: ...
    @property
    def binaries(self) -> list[bytes]: ...
    def add_binary(
        self, data: bytes, compressed: bool = True, protected: bool = True
    ) -> int: ...
    def delete_binary(self, id: int) -> None: ...

    # --- Misc ---

    def deref(self, value: str | None) -> str | _uuid.UUID | None: ...

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
