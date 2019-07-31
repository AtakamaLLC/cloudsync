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
    hash: bytes                            # fsobject hash     (better name: ohash)
    path: Optional[str]                    # path


class DirInfo(OInfo):
    name = ""

    def __init__(self, *a, name=None, **kw):
        super().__init__(*a, **kw)
        self.name = name
