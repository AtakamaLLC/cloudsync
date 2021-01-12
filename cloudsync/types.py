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


@dataclass  # pylint: disable=too-many-instance-attributes
class OInfo:
    """Base class for object returned by info_oid, info_path, create and listdir"""
    otype: OType                           # fsobject type     (DIRECTORY or FILE)
    oid: str                               # fsobject id
    hash: Any                              # fsobject hash     (better name: ohash)
    path: Optional[str]                    # path
    size: int = 0                          # size of object in bytes
    name: Optional[str] = None             # just the filename, without the path, when the full path is expensive
    mtime: Optional[float] = None          # modification time
    shared: bool = False                   # file is shared by the cloud provider
    readonly: bool = False                 # file is readonly in the cloud
    custom: Optional[Any] = None          # dict of provider specific information


@dataclass
class DirInfo(OInfo):
    pass
