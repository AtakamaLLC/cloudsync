"""
Base types for cloudsync
"""
from typing import Optional, Any
from enum import Enum
from dataclasses import dataclass


# these are not really local or remote
# but it's easier to reason about using these labels
LOCAL = 0
REMOTE = 1


class OType(Enum):
    DIRECTORY = "dir"
    FILE = "file"
    NOTKNOWN = "trashed"


class IgnoreReason(Enum):
    NONE = "none"
    DISCARDED = "discarded"
    CONFLICT = "conflict"
    TEMP_RENAME = "temp rename"
    IRRELEVANT = "irrelevant"


DIRECTORY = OType.DIRECTORY
FILE = OType.FILE
NOTKNOWN = OType.NOTKNOWN                  # only allowed for deleted files!


@dataclass
class OInfo:
    otype: OType                           # fsobject type     (DIRECTORY or FILE)
    oid: str                               # fsobject id
    hash: Any                              # fsobject hash     (better name: ohash)
    path: Optional[str]                    # path
    size: int = 0                          # size of object in bytes


@dataclass
class DirInfo(OInfo):
    name: Optional[str] = None
    mtime: Optional[float] = None
    shared: bool = False
    readonly: bool = False
