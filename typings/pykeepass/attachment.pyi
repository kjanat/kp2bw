from lxml.etree import Element

from .entry import Entry
from .pykeepass import PyKeePass

class Attachment:
    _element: Element
    _kp: PyKeePass

    def __init__(
        self,
        element: Element | None = ...,
        kp: PyKeePass | None = ...,
        id: int | None = ...,
        filename: str | None = ...,
    ) -> None: ...
    @property
    def id(self) -> int: ...
    @id.setter
    def id(self, id: int) -> None: ...
    @property
    def filename(self) -> str: ...
    @filename.setter
    def filename(self, filename: str) -> None: ...
    @property
    def entry(self) -> Entry: ...
    @property
    def binary(self) -> bytes: ...

    data: bytes

    def delete(self) -> None: ...
