from typing import NamedTuple
from enum import Enum


class OType(Enum):
    DIRECTORY = "dir"
    FILE = "file"


DIRECTORY = OType.DIRECTORY
FILE = OType.FILE


class OInfo(NamedTuple):             # todo, rename to FileInfo
    otype: OType                           # fsobject type     (DIRECTORY or FILE)
    oid: str                               # fsobject id
    hash: bytes                            # fsobject hash     (better name: ohash)
    path: str                              # path


class ListDirOInfo(OInfo):
    name = ""

    def __new__(cls, *a, name=None, **kwargs):
        self = super().__new__(cls, *a, **kwargs)
        self.name = name
        return self
