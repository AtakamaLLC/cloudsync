from typing import Optional
from dataclasses import dataclass
from enum import Enum


class OType(Enum):
    DIRECTORY = "dir"
    FILE = "file"


DIRECTORY = OType.DIRECTORY
FILE = OType.FILE


@dataclass
class OInfo:
    otype: OType                           # fsobject type     (DIRECTORY or FILE)
    oid: str                               # fsobject id
    hash: Optional[bytes]                  # fsobject hash     (better name: ohash)
    path: Optional[str]                    # path


@dataclass
class DirInfo(OInfo):
    name: Optional[str] = None
    mtime: Optional[float] = None
