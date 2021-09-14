# pylint: disable=attribute-defined-outside-init, protected-access, too-many-lines, missing-docstring
"""
SyncEntry[SideState, SideState] is a pair of entries, indexed by oid.  The SideState class makes
extensive use of __getattr__ logic to keep indexes up to date.

There may be no need to keep them in "pairs".   This is artificial. States should probably be
altered to independent, and not paired at all.
"""

import copy
import logging
import time
import os
import random
from threading import RLock
from abc import ABC, abstractmethod
from enum import Enum
import datetime
from typing import Optional, Tuple, Any, List, Dict, Set, cast, TYPE_CHECKING, Callable, Generator, overload

from typing import Union, Sequence
import msgpack
from pystrict import strict

from cloudsync.types import DIRECTORY, FILE, NOTKNOWN, IgnoreReason, LOCAL, REMOTE, OInfo
from cloudsync.types import OType
from cloudsync.log import TRACE
from cloudsync.utils import debug_sig, disable_log_multiline
from cloudsync.notification import NotificationManager

if TYPE_CHECKING:
    from cloudsync import Provider

log = logging.getLogger(__name__)
OTHER_SIDE = (1, 0)

__all__ = ['SyncState', 'SideState', 'SyncStateLookup', 'SyncEntry', 'Storage',
           'FILE', 'DIRECTORY', 'UNKNOWN', 'MISSING', 'TRASHED', 'EXISTS', 'LIKELY_TRASHED', 'OTHER_SIDE', 'CORRUPT']
# safe ternary, don't allow traditional comparisons


class Exists(Enum):
    """
    Whether a file exists, used throughout the system instead of booleans
    """
    UNKNOWN = "unknown"
    EXISTS = "exists"
    TRASHED = "trashed"
    MISSING = "missing"
    LIKELY_TRASHED = "likely-trashed"           # this oid was trashed, but then another event came in saying it wasn't
    CORRUPT = "corrupt"

    def __bool__(self):
        """
        Protect against bool use
        """
        raise ValueError("never bool enums")


UNKNOWN = Exists.UNKNOWN
EXISTS = Exists.EXISTS
TRASHED = Exists.TRASHED
LIKELY_TRASHED = Exists.LIKELY_TRASHED
MISSING = Exists.MISSING
CORRUPT = Exists.CORRUPT


# state of a single object
@strict         # pylint: disable=too-many-instance-attributes
class SideState:
    """
    One half of a sync
    """
    hash: Any
    sync_hash: Any

    def __init__(self, parent: 'SyncEntry', side: int, otype: Optional[OType]):
        self._parent = parent
        self._side: int = side
        self._otype: Optional[OType] = otype
        self._hash: Optional[bytes] = None           # hash at provider
        # time of last change (we maintain this)
        self._changed: Optional[float] = None
        self._last_gotten: float = 0.0               # set to == changed when getting
        self._sync_hash: Optional[bytes] = None      # hash at last sync
        self._sync_path: Optional[str] = None        # path at last sync
        self._path: Optional[str] = None             # path at provider
        self._oid: Optional[str] = None              # oid at provider
        self._exists: Exists = UNKNOWN               # exists at provider
        self._force_sync: bool = False
        self._temp_file: Optional[str] = None
        self.temp_file: str
        self._size: Optional[int] = None
        self._mtime: Optional[float] = None
        self._saved_exists: Optional[Exists] = None

    def _set_mtime(self, value):
        if isinstance(value, datetime.datetime):
            value = value.timestamp()
        assert value is None or isinstance(value, (int, float))
        self._mtime = value
        self._parent.updated(self._side, "mtime", value)

    def __getattr__(self, k):
        if k[0] != "_":
            return getattr(self, "_" + k)
        raise AttributeError("%s not in SideState" % k)

    def __setattr__(self, k, v):
        if k[0] == "_":
            object.__setattr__(self, k, v)
            return

        if k == "exists":
            if v == CORRUPT and not self.is_corrupt:
                # see comment on the SideState.is_corrupt method for more information on the corrupt state
                self._saved_exists = self.exists
                self._exists = v
                return
            if v != CORRUPT and self.is_corrupt:
                self._saved_exists = self._translate_exists(v)
                return

        self._parent.updated(self._side, k, v)

        if k == "exists":
            self._set_exists(v)
        elif k == "mtime":
            self._set_mtime(v)
        else:
            if k == "hash" and self._hash != v and self.is_corrupt:
                self.uncorrupt()
            object.__setattr__(self, "_" + k, v)

    @staticmethod
    def _translate_exists(val):
        if val is False:
            xval = TRASHED
        elif val is True:
            xval = EXISTS
        elif val is None:
            xval = UNKNOWN
        elif type(val) is Exists:
            xval = cast(Exists, val)
        else:
            xval = Exists(val)

        if type(xval) != Exists:
            raise ValueError("use enum for exists")
        return xval

    def _set_exists(self, val: Union[bool, Exists]):
        xval = self._translate_exists(val)
        self._exists = xval
        self._parent.updated(self._side, "exists", xval)

    def mark_changed(self):
        # setting to an old mtime marks this as fully aged
        self._parent.mark_changed(self.side)

    def set_aged(self):
        # setting to an old mtime marks this as fully aged
        self.changed = 1

    def set_force_sync(self):
        self.changed = time.time()  # type: ignore
        self.force_sync = True

    def clear(self):
        self.exists = UNKNOWN
        self.changed = None
        self.hash = None
        self.sync_hash = None
        self.sync_path = None
        self.path = None
        self.oid = None
        self.size = None
        self.mtime = None

    def __repr__(self):
        d = self.__dict__.copy()
        d.pop("_parent", None)
        return self.__class__.__name__ + ":" + debug_sig(id(self)) + str(d)

    def needs_sync(self):
        if self.force_sync:
            return True
        return self.changed and self.oid and (
               self.hash != self.sync_hash or
               self.parent.paths_differ(self.side) or
               self.exists in (TRASHED, LIKELY_TRASHED, MISSING))

    def clean_temp(self):
        if self.temp_file:
            try:
                os.unlink(self.temp_file)
            except FileNotFoundError:
                pass
            except OSError as e:
                log.debug("exception unlinking %s", e)
            except Exception as e:  # any exceptions here are pointless
                log.warning("exception unlinking %s", e)
                self.temp_file = None

    @property
    def is_corrupt(self):
        # A SideState is considered "corrupt" when a provider raises the CloudCorruptError from the download method.
        # This can occur if a block is bad on disk, or any other reason why the file may be unreadable.
        # If a file is corrupt, then the assumption is that we do not want to sync the corrupt file to the other side.
        # Also, we assume that the corrupt version of the file may be deleted or renamed to move it out of the way,
        #   and syncing these deletions or renames to the other side is unwanted, and should be ignored. When the file
        #   is replaced with a new version (meaning a new hash is present on the corrupt side) then the assumption is
        #   that this is the new, not corrupt, version, and should be synced. If the file is still corrupt, then the
        #   download method will raise the CloudCorruptError again, and the file will go back to being corrupt.
        # Additionally, since the file is corrupt, the known good file from the other side will be downloaded to
        #   overwrite the known bad file, which should un-corrupt the file and leave it synced at an older version.
        return self.exists == CORRUPT

    def uncorrupt(self):
        if self.is_corrupt:
            self._set_exists(self._saved_exists)
            self._saved_exists = None

    @property
    def corrupt_exists(self):
        return self.is_corrupt and self._saved_exists == EXISTS

    @property
    def corrupt_gone(self):
        return self.is_corrupt and self._saved_exists in (TRASHED, MISSING, LIKELY_TRASHED)

    def serialize(self) -> dict:
        ret = dict()
        ret['otype'] = self.otype.value
        ret['side'] = self.side
        ret['hash'] = self.hash
        ret['changed'] = self.changed
        ret['sync_hash'] = self.sync_hash
        ret['path'] = self.path
        ret['sync_path'] = self.sync_path
        ret['oid'] = self.oid
        ret['exists'] = self.exists.value
        ret['temp_file'] = self.temp_file
        ret['size'] = self.size
        ret['mtime'] = self.mtime
        ret['_saved_exists'] = None if self._saved_exists is None else self._saved_exists.value
        # storage_id does not get serialized, it always comes WITH a serialization when deserializing
        return ret

    def deserialize(self, serialization: dict):
        self.otype = OType(serialization['otype'])
        self.side = serialization['side']
        self.hash = serialization['hash']
        self.changed = serialization['changed']
        self.sync_hash = serialization['sync_hash']
        self.sync_path = serialization['sync_path']
        self.oid = serialization['oid']
        self.path = serialization['path']
        # back compat: 10/21/19
        if serialization['exists'] is None:
            self.exists = UNKNOWN
        if serialization['exists'] is True:
            self.exists = EXISTS
        if serialization['exists'] is False:
            self.exists = TRASHED
        self.exists = serialization['exists']
        self.temp_file = serialization['temp_file']
        self.size = serialization.get('size')
        self.mtime = serialization.get('mtime')
        saved_exists = serialization.get('_saved_exists')
        try:
            self._saved_exists = Exists(saved_exists) if saved_exists else None
        except ValueError:
            log.error('bad saved value %s for _saved_exists for %s', serialization.get('_saved_exists'), self.path)
            self._saved_exists = UNKNOWN


def other_side(index):  # pragma: no cover
    # This method is deprecated, in favor of the OTHER_SIDE tuple
    return 1-index


class Storage(ABC):
    """
    Abstract base storage class
    """
    @abstractmethod
    def create(self, tag: str, serialization: bytes) -> Any:
        """ take a serialization str, upsert it in sqlite, return the row id of the row as a persistence id"""
        ...

    @abstractmethod
    def update(self, tag: str, serialization: bytes, eid: Any) -> int:
        """ take a serialization str, update it in sqlite, return the count of rows updated """
        ...

    @abstractmethod
    def delete(self, tag: str, eid: Any):
        """ take a serialization str, look up the eid, and delete the row with that eid"""
        ...

    @overload
    @abstractmethod
    def read_all(self) -> Dict[str, Dict[Any, bytes]]:
        """yield all the serialized strings in a generator"""
        ...

    @overload
    @abstractmethod
    def read_all(self, tag: str) -> Dict[Any, bytes]:
        """yield all the serialized strings in a generator"""
        ...

    @abstractmethod
    def read_all(self, tag=None):
        """yield all the serialized strings in a generator"""
        ...

    @abstractmethod
    def read(self, tag: str, eid: Any) -> Optional[bytes]:
        """return one serialized string or None"""
        ...


# single entry in the syncs state collection
@strict         # pylint: disable=too-many-instance-attributes, too-many-public-methods
class SyncEntry:
    """
    A pair of side states, as well as their storage information, and sync priority.
    """
    def __init__(self, parent: 'SyncState',
                 otype: Optional[OType],
                 storage_init: Optional[Tuple[Any, bytes]] = None,
                 ignore_reason: IgnoreReason = IgnoreReason.NONE):
        super().__init__()
        assert otype is not None or storage_init
        self.__states: List[SideState] = [SideState(self, 0, otype), SideState(self, 1, otype)]
        self._ignored = ignore_reason
        self._storage_id: Any = None
        self._priority: float = 0         # 0 == normal, > 0 == high, < 0 == low
        self._parent = parent

        if storage_init is not None:
            self._storage_id = storage_init[0]
            self.deserialize(storage_init)
        log.debug("new syncent %s", debug_sig(id(self)))

        self.priority: float

    def __getattr__(self, k):
        if k[0] != "_":
            return getattr(self, "_" + k)
        raise AttributeError("%s not in SyncEntry" % k)

    def __setattr__(self, k, v):
        if k[0] == "_":
            object.__setattr__(self, k, v)
            return

        if getattr(self, "_" + k) != v:
            self.updated(None, k, v)
            object.__setattr__(self, "_" + k, v)

    def mark_changed(self, side):
        self._parent.mark_changed(side, self)

    def updated(self, side, key, val):
        self._parent.updated(self, side, key, val)

    def serialize(self) -> bytes:
        """converts SyncEntry into a json str"""
        ser: Dict[str, Any] = dict()
        ser['side0'] = self.__states[0].serialize()
        ser['side1'] = self.__states[1].serialize()
        ser['ignored'] = self._ignored.value
        ser['priority'] = self._priority
        try:
            return msgpack.dumps(ser, use_bin_type=True)
        except TypeError:
            log.exception("Could not serialize SyncEntry: %s", ser)
            raise

    def deserialize(self, storage_init: Tuple[Any, bytes]):
        """loads the values in the serialization dict into self"""
        self.storage_id = storage_init[0]
        ser: dict = msgpack.loads(storage_init[1], use_list=False, raw=False)
        self.__states[0].deserialize(ser['side0'])
        self.__states[1].deserialize(ser['side1'])
        reason_string = ser.get('ignored', "")
        if reason_string:
            if reason_string == "trashed":
                reason_string = "discarded"
            try:
                reason = IgnoreReason(reason_string)
                self._ignored = reason
            except ValueError:  # reason was specified, but had an unrecognized value?
                log.warning("deserializing state, but ignored had bad value %s", reason_string)
                reason = IgnoreReason.DISCARDED
        elif ser.get('discarded', ""):
            self._ignored = IgnoreReason.DISCARDED
        elif ser.get('conflicted', ""):
            self._ignored = IgnoreReason.CONFLICT

        ser['priority'] = ser.get('priority', 0)

    def __getitem__(self, i):
        return self.__states[i]

    def __setitem__(self, side, val):
        # can't really move items.. just copy stuff
        new_path = val._path
        new_oid = val._oid

        # old value is no longer in charge of anything
        val.path = None
        val.oid = None

        # new value rulez
        val = copy.copy(val)
        val._path = new_path
        val._oid = new_oid
        val._parent = self

        assert type(val) is SideState
        assert val.side == side

        # we need to ensure a valid oid is present when changing the path
        if val._oid is None:
            self.updated(side, "path", val._path)
            self.updated(side, "oid", val._oid)
        else:
            self.updated(side, "oid", val._oid)
            self.updated(side, "path", val._path)

        self.updated(side, "changed", val._changed)

        self.__states[side] = copy.copy(val)

    def hash_conflict(self):
        if self[0].hash and self[1].hash and self[0].path and self[1].path:
            return self[0].hash != self[0].sync_hash and self[1].hash != self[1].sync_hash
        return False

    def is_path_change(self, changed):
        return self[changed].sync_path and self.paths_differ(changed)

    def is_deletion(self, side):
        return self[OTHER_SIDE[side]].exists == EXISTS and self[side].exists in (TRASHED, MISSING) and self[side].changed

    def is_creation(self, side):
        if self[side].path and self[side].exists == EXISTS:
            if self[side].needs_sync():
                return not self[OTHER_SIDE[side]].oid or self[OTHER_SIDE[side]].exists in (TRASHED, MISSING)
            else:
                return self[OTHER_SIDE[side]].is_corrupt
        return False

    def is_rename(self, changed):
        return self[changed].sync_path and self[changed].path and self.paths_differ(changed)

    def paths_match(self, side):
        prov = self.parent.providers[side]
        return prov.paths_match(self[side].sync_path, self[side].path, for_display=True)

    def paths_differ(self, side):
        return not self.paths_match(side)

    def needs_sync(self):
        return self[LOCAL].needs_sync() or self[REMOTE].needs_sync()

    @property
    def is_discarded(self):
        return self.ignored in (IgnoreReason.DISCARDED, IgnoreReason.IRRELEVANT)

    @property
    def is_irrelevant(self):
        return self.ignored == IgnoreReason.IRRELEVANT

    @property
    def is_conflicted(self):
        return self.ignored == IgnoreReason.CONFLICT

    @property
    def is_trash(self):
        return self[LOCAL].oid is None and self[REMOTE].oid is None

    @property
    def is_temp_rename(self):
        return self.ignored == IgnoreReason.TEMP_RENAME

    def ignore(self, reason: IgnoreReason, previous_reasons: Union[Sequence[IgnoreReason], IgnoreReason] = (IgnoreReason.NONE,)):
        if isinstance(previous_reasons, IgnoreReason):
            previous_reasons = (previous_reasons,)

        # always ok to set the target reason if the current reason is none or is already the target reason
        if self._ignored not in (IgnoreReason.NONE, reason, *previous_reasons):
            log.warning("Ignoring entry for reason '%s' that should have been '%s' already, but was actually '%s':%s",
                        reason.value, [x.value for x in previous_reasons], self._ignored, self)
        if reason == IgnoreReason.NONE:
            log.warning("don't call ignore(IgnoreReason.NONE), call unignore() with the reason to stop ignoring")
        self.ignored = reason

    def unignore(self, reason: IgnoreReason):
        assert self.ignored in (reason, IgnoreReason.NONE)
        self.ignored = IgnoreReason.NONE

    @staticmethod
    def prettyheaders():
        ret = "%3s %3s %3s %6s %20s %6s %22s -- %6s %20s %6s %22s %s %s" % (
            "EID",  # _sig(id(self)),
            "SID",  # _sig(self.storage_id),
            "Typ",  # otype,
            "Change",  # secs(self[LOCAL].changed),
            "Path",  # self[LOCAL].path,
            "OID",  # _sig(self[LOCAL].oid),
            "Last Sync Path E H",  # str(self[LOCAL].sync_path) + ":" + lexv + ":" + lhma,
            "Change",  # secs(self[REMOTE].changed),
            "Path",  # self[REMOTE].path,
            "OID",  # _sig(self[REMOTE].oid),
            "Last Sync Path    ",  # str(self[REMOTE].sync_path) + ":" + rexv + ":" + rhma,
            "Priority",  # self.priority or ""
            "Ignored",  # self.ignored or ""
        )
        return ret

    def pretty_summary(self, use_sigs=True):
        def secs(t):
            if t:
                if t >= self.parent._pretty_time:
                    return str(int(1000*round(t-self.parent._pretty_time, 3)))
                return -t
            else:
                return 0

        def abbrev_exists(v):
            return v.value[0].upper()

        def abbrev_equiv(a, b, table):
            assert len(table) == 5                  # quick check
            if a is None and b is not None:
                return table["rightonly"]
            if a is not None and b is None:
                return table["leftonly"]
            if a is None and b is None:
                return table["neither"]
            if a == b:
                return table["equiv"]
            else:
                return table["mismatch"]

        lexv = abbrev_exists(self[LOCAL].exists)
        rexv = abbrev_exists(self[REMOTE].exists)
        abbrev_table = {
            "mismatch": "H",
            "leftonly": "<",
            "rightonly": ">",
            "equiv": "=",
            "neither": "0"
        }
        lhma = abbrev_equiv(self[LOCAL].hash, self[LOCAL].sync_hash, abbrev_table)
        rhma = abbrev_equiv(self[REMOTE].hash, self[REMOTE].sync_hash, abbrev_table)

        _sig: Callable[[Any], Any]
        if use_sigs:
            _sig = debug_sig
        else:
            _sig = lambda a: a      # noqa

        if use_sigs:
            _secs = secs
        else:
            _secs = lambda a: a     # noqa

        local_otype = self[LOCAL].otype.value if self[LOCAL].otype else '?'
        remote_otype = self[REMOTE].otype.value if self[REMOTE].otype else '?'

        if local_otype != remote_otype:
            otype = local_otype[0] + "-" + remote_otype[0]
        else:
            otype = local_otype

        return (
            _sig(id(self)),
            _sig(self.storage_id),
            otype[:3],

            _secs(self[LOCAL].changed),
            self[LOCAL].path,
            _sig(self[LOCAL].oid),
            str(self[LOCAL].sync_path), lexv, lhma,

            _secs(self[REMOTE].changed),
            self[REMOTE].path,
            _sig(self[REMOTE].oid),
            str(self[REMOTE].sync_path), rexv, rhma,

            self._priority or "",
            self.ignored.value if self.ignored.value != IgnoreReason.NONE else "",
            )

    def pretty_tuple(self, use_sigs=True):  # pretty(fixed=False) becomes pretty_tuple()
        s = self.pretty_summary(use_sigs=use_sigs)
        return (s[0], s[1], s[2],
                (s[3], s[4], s[5], ":".join(s[6:9])),
                (s[9], s[10], s[11], ":".join(s[12:15])),
                s[15], s[16])

    @staticmethod
    def pretty_format(widths, sep="|"):
        formats = ["%" + str(w) + "s" for w in widths]
        format_str = sep.join(formats[0:9]) + sep + "--" + sep + sep.join(formats[9:17])
        return format_str

    def pretty(self, use_sigs=True, summary=None, widths=None):  # pretty() or pretty(fixed=True) becomes pretty()
        summary = summary or self.pretty_summary(use_sigs=use_sigs)
        if widths is None:
            widths = (3, 3, 3, 6, 20, 6, 20, 1, 1, 6, 20, 6, 20, 1, 1, 0, 0)
        format_string = SyncEntry.pretty_format(widths)
        ret = ""  # if self.ignored == IgnoreReason.NONE else "# "
        ret += format_string % tuple(summary)
        return ret

    def __str__(self):
        return str(self.pretty_tuple())

    def __repr__(self):
        return str(self.pretty_tuple())

    def store(self, tag: str, storage: Storage):
        if not self.storage_id:
            self.storage_id = storage.create(tag, self.serialize())
        else:
            storage.update(tag, self.serialize(), self.storage_id)

    def punt(self):
        # do this one later
        self.priority += 1

    def get_latest(self, force=False):
        max_changed = max(self[LOCAL].changed or 0, self[REMOTE].changed or 0)
        for side in (LOCAL, REMOTE):
            if force or max_changed > self[side]._last_gotten:
                self._parent.unconditionally_get_latest(self, side)
                self[side]._last_gotten = max_changed

    def mark_dirty(self, side):
        self[side]._last_gotten = 0

    def is_latest(self) -> bool:
        max_changed = max(self[LOCAL].changed or 0, self[REMOTE].changed or 0)
        for side in (LOCAL, REMOTE):
            if max_changed > self[side]._last_gotten:
                return False
        return True

    def is_latest_side(self, side: int) -> bool:
        max_changed = max(self[LOCAL].changed or 0, self[REMOTE].changed or 0)
        return max_changed <= self[side]._last_gotten

    def is_related_to(self, e):
        for side in (LOCAL, REMOTE):
            for attr in ("path", "sync_path"):
                if getattr(self[side], attr, None) and getattr(e[side], attr) == self._parent.providers[LOCAL].dirname(getattr(self[side], attr)):
                    return True
                if getattr(e[side], attr, None) and getattr(self[side], attr) == self._parent.providers[LOCAL].dirname(getattr(e[side], attr)):
                    return True
        return False


@strict
class SyncState:  # pylint: disable=too-many-instance-attributes, too-many-public-methods
    """
    Holds the entire sync engine state.

    Args:
        providers: pair of providers
        storage: optional `Storage`
        tag: unique string within `Storage` for this table of entries
        prioritize: callable that, given a path, returns a priority

    """
    headers = (
        "EID",  # _sig(id(self)),
        "SID",  # _sig(self.storage_id),
        "Typ",  # otype,
        "Change",  # secs(self[LOCAL].changed),
        "Path",  # self[LOCAL].path,
        "OID",  # _sig(self[LOCAL].oid),
        "Sync Path",  # str(self[LOCAL].sync_path)
        "E",  # lexv
        "H",  # lhma
        "Change",  # secs(self[REMOTE].changed),
        "Path",  # self[REMOTE].path,
        "OID",  # _sig(self[REMOTE].oid),
        "Sync Path",  # str(self[REMOTE].sync_path)
        "E",  # rexv
        "H",  # rhma
        "Prio",  # self.priority or ""
        "Ignored",  # self.ignored or ""
    )

    def __init__(self,
                 providers: Tuple['Provider', 'Provider'],
                 storage: Optional[Storage] = None,
                 tag: Optional[str] = None,
                 shuffle: bool = False,
                 prioritize: Callable[[int, str], int] = None,
                 nmgr: NotificationManager = None):
        self._oids: Tuple[Dict[Any, SyncEntry], Dict[Any, SyncEntry]] = ({}, {})
        self._paths: Tuple[Dict[str, Dict[Any, SyncEntry]], Dict[str, Dict[Any, SyncEntry]]] = ({}, {})
        self._changeset_storage: Set[SyncEntry] = set()
        self._dirtyset: Set[SyncEntry] = set()
        self._storage: Optional[Storage] = storage
        self._tag = tag
        self._nmgr = nmgr or NotificationManager(lambda e: None)
        self.providers = providers
        self._punt_secs = (providers[0].default_sleep/10.0, providers[1].default_sleep/10.0)
        self._pretty_time = time.time()
        self._last_changed_time = time.time()
        assert len(providers) == 2

        self.lock = RLock()
        self.data_id: Dict[str, Any] = dict()
        self.shuffle = shuffle
        self._loading = False
        if self._storage:
            assert self._tag
            self._loading = True
            storage_dict = self._storage.read_all(cast(str, tag))
            for eid, ent_ser in storage_dict.items():
                try:
                    ent = SyncEntry(self, None, (eid, ent_ser))
                    for side in [LOCAL, REMOTE]:
                        path, oid = ent[side].path, ent[side].oid
                        if path not in self._paths[side]:
                            self._paths[side][path] = {}
                        self._paths[side][path][oid] = ent
                        self._oids[side][oid] = ent
                        if ent[side].changed:
                            self._changeset_storage.add(ent)
                except Exception as e:
                    log.error("exception during deserialization %s", e)
                    self._storage.delete(tag, eid)
            self._loading = False
        self.prioritize = prioritize
        if prioritize is None:
            self.prioritize = lambda side, path: 0

    @property
    def _changeset(self):
        return self._changeset_storage

    @_changeset.setter
    def _changeset(self, value):
        self._changeset_storage = value

    def forget_oid(self, side, oid):
        ent = self._oids[side].pop(oid, None)
        if ent:
            self._paths[side][ent[side].path].pop(oid)

    def forget(self):
        self._oids = ({}, {})
        self._paths = ({}, {})
        self._changeset = set()
        self._dirtyset = set()
        self.data_id = {}
        if self._storage:
            storage_dict = self._storage.read_all(cast(str, self._tag))
            for eid, _ in storage_dict.items():
                self._storage.delete(self._tag, eid)

    def updated(self, ent, side, key, val):     # pylint: disable=too-many-branches
        if self._loading:
            return

        assert key

        if key == "path":
            self._change_path(side, ent, val, self.providers[side])
        elif key == "oid":
            self._change_oid(side, ent, val)
        elif key == "ignored":
            if val == IgnoreReason.DISCARDED:
                ent[LOCAL]._changed = False
                ent[REMOTE]._changed = False
                self._changeset_storage.discard(ent)
        elif key == "changed":
            if (val and ent[side].oid) or (ent[OTHER_SIDE[side]].changed and ent[OTHER_SIDE[side]].oid):
                self._changeset_storage.add(ent)
            else:
                self._changeset_storage.discard(ent)
                if ent[other_side(side)].changed and not ent[other_side(side)].oid:
                    ent[other_side(side)].changed = 0  # otherwise there is a change that is not in the changeset
        elif key == "priority":
            if val > ent.priority and val > 0:
                # move to later on priority drop below zero
                if ent[LOCAL].changed:
                    ent[LOCAL].changed += ent._parent._punt_secs[LOCAL]
                if ent[REMOTE].changed:
                    ent[REMOTE].changed += ent._parent._punt_secs[REMOTE]

        self._dirtyset.add(ent)

    @property
    def changes(self):
        return tuple(self._changeset)

    @property
    def changeset_len(self):
        return len(self._changeset)

    def _change_path(self, side, ent, path, provider):
        assert type(ent) is SyncEntry
        if path:
            assert ent[side].oid

        prior_ent = ent
        prior_path = ent[side].path
        if prior_path == path:
            return

        if prior_path and prior_path in self._paths[side]:
            prior_ent = self._paths[side][prior_path].pop(ent[side].oid, None)
            if not self._paths[side][prior_path]:
                del self._paths[side][prior_path]
            prior_ent = None

        if path:
            if path not in self._paths[side]:
                self._paths[side][path] = {}

            path_ents = self._paths[side][path]
            if ent[side].oid in path_ents:
                prior_ent = path_ents[ent[side].oid]
                assert prior_ent is not ent
                # ousted this ent
                prior_ent[side]._path = None

            self._paths[side][path][ent[side].oid] = ent
            ent[side]._path = path

            self._update_kids(ent, side, prior_path, path, provider)

            new_priority = self.prioritize(side, path)
            if new_priority != ent.priority:
                ent.priority = new_priority

    def _update_kids(self, ent, side, prior_path, path, provider: 'Provider'):
        if ent[side].otype == DIRECTORY and prior_path != path and not prior_path is None:
            # changing directory also changes child paths
            for sub, relative in self.get_kids(prior_path, side):
                new_path = provider.join(path, relative)
                if provider.oid_is_path:
                    # TODO: state should not do online hits esp from event manager
                    # either
                    # a) have event manager *not* trigger this, maybe by passing none as the provider, etc
                    #    this may have knock on effects where the sync engine needs to process parent folders first
                    # b) have a special oid_from_path function that is guaranteed not to be "online"
                    #    assert not _api() called, etc.
                    new_info = provider.info_path(new_path)
                    if new_info:
                        sub[side].oid = new_info.oid
                sub[side].path = new_path

                # now do the same thing for the sync_path
                # do not change path! this can cause weird recursion, also it's wrong
                # you're not changing what it *should be* (path)
                # just what it is (sync_path)
                if sub[side].sync_path:
                    sync_rel = provider.is_subpath(prior_path, sub[side].sync_path)
                    if sync_rel:
                        new_sync_path = provider.join(path, sync_rel)
                        sub[side].sync_path = new_sync_path


    def _change_oid(self, side, ent, oid):
        assert type(ent) is SyncEntry

        for remove_oid in set([ent[side].oid, oid]):
            prior_ent = self._oids[side].pop(remove_oid, None)

            if prior_ent:
                if prior_ent[side].path:
                    prior_path = prior_ent[side].path
                    if prior_path in self._paths[side]:
                        self._paths[side][prior_path].pop(remove_oid, None)
                        if not self._paths[side][prior_path]:
                            del self._paths[side][prior_path]

                if prior_ent is not ent:
                    # no longer indexed by oid, also clear change bit
                    prior_ent[side].oid = None

        if oid is not None:
            ent[side]._oid = oid
            self._oids[side][oid] = ent

            assert self.lookup_oid(side, oid) is ent

        if oid is not None and ent[side].path:
            if ent[side].path not in self._paths[side]:
                self._paths[side][ent[side].path] = {}
            self._paths[side][ent[side].path][oid] = ent

        if oid is not None:
            # ent with oid goes in changeset
            assert self.lookup_oid(side, oid) is ent
            if ent[side].changed or ent[OTHER_SIDE[side]].changed:
                self._changeset_storage.add(ent)
        else:
            # ent without oid doesn't go in changeset
            if ent[side].changed and not ent[OTHER_SIDE[side]].changed:
                self._changeset_storage.discard(ent)

    def lookup_creation(self, content_hash, side):
        for ent in self.get_all():
            if ent[side].otype != FILE or ent[side].hash != content_hash:
                continue
            ent.get_latest()  # ent may not have the path yet, which will confuse is_creation()
            if ent.is_creation(side):
                return ent
        return None

    def lookup_deletion(self, content_hash, side):
        for ent in self.get_all():
            if ent[side].hash == content_hash and ent.is_deletion(side):
                return ent
        return None

    def get_kids(self, parent_path: str, side: int) -> Generator[Tuple[SyncEntry, str], None, None]:
        provider = self.providers[side]
        for sub in self.get_all():
            if not sub[side].path:
                continue
            relpath = provider.is_subpath(parent_path, sub[side].path, strict=True)
            if relpath:
                yield sub, relpath

    def lookup_oid(self, side, oid) -> SyncEntry:
        try:
            ret = self._oids[side][oid]
            return ret
        except KeyError:
            return None

    def lookup_path(self, side, path, stale=False) -> List[SyncEntry]:
        try:
            ret: Sequence[SyncEntry] = list(self._paths[side][path].values())
            if ret:
                return [e for e in ret if stale or (not e.is_discarded and not e.is_conflicted)]
            return []
        except KeyError:
            return []

    def rename_dir(self, side, from_dir, to_dir, is_subpath, replace_path):
        """
        when a directory changes, utility to rename all kids
        """
        remove = []

        # TODO: refactor this so that a list of affected items is gathered, then the alterations happen to the final
        #    list, which will avoid having to remove after adding, which feels mildly risky
        # TODO: is this function called anywhere? ATM, it looks like no... It should be called or removed
        for path, oid_dict in self._paths[side].items():
            if is_subpath(from_dir, path):
                new_path = replace_path(path, from_dir, to_dir)
                remove.append(path)
                self._paths[side][new_path] = oid_dict
                for ent in oid_dict.values():
                    ent[side].path = new_path

        for path in remove:
            self._paths[side].pop(path)

    def update_entry(self, ent, side, oid, *, path=None, file_hash=None, exists=True, changed=False, otype=None, size=None, mtime=None, accurate=False):  # pylint: disable=redefined-builtin, too-many-arguments, too-many-branches
        assert ent

        if oid is not None:
            if ent.is_discarded:
                if self.providers[side].oid_is_path:
                    if path and otype:
                        log.log(TRACE, "dropping old entry %s, and making new", ent)
                        ent = SyncEntry(self, otype)

            ent[side].oid = oid

        if otype is not None and otype != ent[side].otype:
            ent[side].otype = otype

        if size is not None:
            ent[side].size = size

        if mtime is not None:
            ent[side].mtime = mtime

        assert otype is not NOTKNOWN or not exists

        if path is not None:
            new_path = self.providers[side].normalize_path_separators(path)
            if new_path != ent[side].path:
                ent[side].path = new_path

        if file_hash is not None and file_hash != ent[side].hash:
            ent[side].hash = file_hash

        if ent[side].exists is TRASHED and exists is True:
            # oid was deleted, and then re-created, this can only happen for oid-is-path providers
            # we mark it as LIKELY_TRASHED, to protect against out-of-order events
            # see: https://vidaid.atlassian.net/browse/VFM-7246
            ent[side].exists = LIKELY_TRASHED
        else:
            ent[side].exists = exists

        if changed:
            assert ent[side].path or ent[side].oid
            log.log(TRACE, "add %s to changeset", ent)
            self.mark_changed(side, ent)

            if accurate:
                ent[side]._last_gotten = changed


        log.log(TRACE, "updated %s", ent)

    def mark_changed(self, side, ent):
        ent[side].changed = time.time()
        # ensure that change times can't repeat and must increase
        # this is a problem on my windows vm, or any machine with a low resolution clock which can
        # produce the same time twice
        # also, this fixes time zone or daylight savings changes where the clock goes backward
        # time.monotonic() would fix the second problem, but not the first
        if ent[side].changed <= self._last_changed_time:
            ent[side].changed = self._last_changed_time + 0.001
        self._last_changed_time = ent[side].changed
        log.debug("change time for side %s is %s", side, ent[side].changed)

    def storage_get_data(self, data_tag):
        if data_tag is None:
            return None
        retval = None
        if self._storage is not None:
            if data_tag in self.data_id:
                retval = self._storage.read(data_tag, self.data_id[data_tag])
            # retval can be 0, but None is reserved
            if retval is None:
                datas = self._storage.read_all(data_tag)
                for eid, data in datas.items():
                    self.data_id[data_tag] = eid
                    retval = data
                if len(datas) > 1:
                    log.warning("Multiple datas found for %s", data_tag)
                    assert False
        log.debug("storage_get_data id=%s data=%s", data_tag, str(retval))
        return retval

    def storage_delete_tag(self, data_tag):
        if self._storage:
            storage_dict = self._storage.read_all(data_tag)
            for eid, _ in storage_dict.items():
                self._storage.delete(data_tag, eid)

    def storage_update_data(self, data_tag, data):
        if data_tag is None:
            return

        # None is reserved, cannot be stored
        assert data is not None

        updated = 0
        if self._storage is not None:
            # stuff cache
            self.storage_get_data(data_tag)
            # data_id's cannot be None, but 0 is valid
            if data_tag in self.data_id and self.data_id[data_tag] is not None:
                updated = self._storage.update(data_tag, data, self.data_id[data_tag])
                log.log(TRACE, "storage_update_data data %s %s -> %s", data_tag, data, updated)
            if not updated:
                self.data_id[data_tag] = self._storage.create(data_tag, data)
                log.log(TRACE, "storage_update_data data CREATE %s %s", data_tag, data)

    def pretty_log_state_table_diffs(self, header="table"):
        try:
            if log.isEnabledFor(TRACE):
                with disable_log_multiline():
                    log.log(TRACE, "%s\n%s", header, self.pretty_print(only_dirty=True))
        except Exception:
            pass  # logging shouldn't be the cause of other things breaking

    def storage_commit(self):
        self.pretty_log_state_table_diffs()
        for ent in self._dirtyset:
            self._storage_update(ent)
        self._dirtyset.clear()

    def _storage_update(self, ent: SyncEntry):
        if self._tag is None:
            return
        tag = cast(str, self._tag)

        log.log(TRACE, "storage_update eid%s", ent.storage_id)
        if self._storage is not None:
            if ent.storage_id is not None:
                if ent.is_trash:
                    self._storage.delete(tag, ent.storage_id)
                else:
                    self._storage.update(tag, ent.serialize(), ent.storage_id)
            else:
                if ent.is_trash:
                    return
                new_id = self._storage.create(tag, ent.serialize())
                ent.storage_id = new_id
                log.debug("storage_update creating eid%s", ent.storage_id)

    def __len__(self):
        return len(self.get_all())

    def update(self, side, otype, oid, path=None, hash=None, exists=True, prior_oid=None, size=None, mtime=None, accurate=False):   # pylint: disable=redefined-builtin, too-many-arguments, disable=too-many-locals
        """Called by the event manager when an event happens."""

        log.log(TRACE, "lookup oid %s, sig %s", oid, debug_sig(oid))
        ent: SyncEntry = self.lookup_oid(side, oid)

        prior_ent = None

        if prior_oid and prior_oid != oid:
            # this is an oid_is_path provider
            prior_ent = self.lookup_oid(side, prior_oid)
            log.debug("prior ent %s", prior_ent)

            # this is only needed when shuffling
            # run test_cs_folder_conflicts_del 100 times or so
            if prior_ent and prior_ent.is_discarded and prior_ent[side].exists in (TRASHED, MISSING):
                ent = prior_ent
                ent.ignored = IgnoreReason.NONE

            if prior_ent and not prior_ent.is_discarded:
                if not ent or (not ent.is_conflicted and (prior_ent[side].sync_hash or not ent[side].sync_hash)):
                    # if we don't have an ent, reuse the prior_ent
                    # otherwise, only consider reusing the prior_ent if it has been synced,
                    #   or if the ent hasn't been synced. if the prior_ent (in a rename this is the "rename from")
                    #   is a short-lived temp file, and the ent (the "rename to") is a long-lived file that is being
                    #   replaced as a result of the rename (as often happens when saving in msoffice), then don't use
                    #   the prior_ent for this reason: the ent has a hash, and the prior_ent doesn't, which can lead
                    #   to unexpected conflicts arising when resolvable or merge-able changes exist in the cloud
                    _copy = None
                    if ent:
                        # copy information about the other side
                        if ent[1-side].oid:
                            _copy = ent[1-side]
                    ent = prior_ent
                    if _copy and not ent[1-side].oid:
                        log.debug("ent was abandoned with copy")
                        ent[1-side] = _copy
                    else:
                        log.debug("ent was abandoned without copy")
            elif not ent:
                path_ents = self.lookup_path(side, path, stale=True)
                for path_ent in path_ents:
                    ent = path_ent
                    ent.unignore(IgnoreReason.DISCARDED)
                    log.debug("matched existing entry %s:%s", debug_sig(oid), path)

        if not ent:
            log.debug("creating new entry because %s not found in %s", debug_sig(oid), side)
            ent = SyncEntry(self, otype)

        self.update_entry(ent, side, oid, path=path, file_hash=hash, exists=exists, changed=time.time(), otype=otype,
                          size=size, mtime=mtime, accurate=accurate)

    def change(self, age):
        change_set = self._changeset
        if not change_set:  # todo: cache the changeset
            return None

        sort_key = lambda a: (a.priority, max(a[LOCAL].changed or 0, a[REMOTE].changed or 0))
        if self.shuffle:
            sort_key = lambda a: (a.priority, random.random())

        changes = sorted(change_set, key=sort_key)

        now = time.time()
        earlier_than = now - age
        for e in changes:
            if (e[LOCAL].changed and (e[LOCAL].changed <= earlier_than)) \
                    or (e[REMOTE].changed and (e[REMOTE].changed <= earlier_than)) \
                    or e.priority < 0:
                return e
            # else:
            #     log.debug("HERE now=%s age=%s earlier_than=%s changed=%s:%s %s", now, age, earlier_than, e[LOCAL].changed, e[REMOTE].changed, e)

        return None

    def finished(self, ent: SyncEntry):
        if not ent[0].changed:
            ent[0].force_sync = False
        if not ent[1].changed:
            ent[1].force_sync = False

        if ent[1].changed or ent[0].changed:
            log.debug("not marking finished: %s", ent)
            return

        log.debug("finished: %s", ent)
        self._changeset_storage.discard(ent)

        for e in self._changeset:
            if e.priority > 0 and ent.is_related_to(e):
                log.debug("%s rel to %s, clearing", ent, e)
                # low priority items are brought back to normal any time a related entry changes
                e.priority = 0

    @staticmethod
    def pretty_headers(widths=None):
        if not widths:
            widths = (3, 3, 3, 6, 20, 6, 20, 1, 1, 6, 20, 6, 20, 1, 1, 0, 0)
        format_string = SyncEntry.pretty_format(widths, sep=" ")
        ret = format_string % SyncState.headers
        return ret

    @staticmethod
    def pretty_sort_key(ent: SyncEntry):
        if ent.ignored != IgnoreReason.NONE:
            return 2
        if ent[LOCAL].changed or ent[REMOTE].changed:
            return 0
        return 1

    def pretty_print(self, use_sigs=True, only_dirty=False):
        ents: List[SyncEntry] = list()
        widths: List[int] = [len(x) for x in SyncState.headers]
        if only_dirty:
            all_ents = self._dirtyset.copy()
        else:
            all_ents = self.get_all(discarded=True)  # allow conflicted to be printed

        e: SyncEntry
        for e in all_ents:
            ents.append(e)
            for i, val in enumerate(e.pretty_summary(use_sigs=use_sigs)):
                width = len(str(val))
                if width > widths[i]:
                    widths[i] = width

        for col, header in enumerate(SyncState.headers):
            if "path" in header.lower():
                widths[col] = 0 - widths[col]

        ret = SyncState.pretty_headers(widths=widths) + "\n"
        found_ignored = False
        for e in sorted(ents, key=self.pretty_sort_key):
            if e.ignored != IgnoreReason.NONE and not found_ignored:
                if not only_dirty:
                    ret += "------\n"
                found_ignored = True
            ret += e.pretty(widths=widths, use_sigs=use_sigs) + "\n"

        return ret

    def assert_index_is_correct(self):
        for ent in self._changeset:
            if not ent.is_discarded and not ent.is_conflicted:
                assert ent in self.get_all(), ("%s in changeset, not in index" % ent)

        for ent in self.get_all():
            assert ent

            if ent[LOCAL].path:
                assert ent in self.lookup_path(LOCAL, ent[LOCAL].path), ("%s local path not indexed" % ent)
            if ent[REMOTE].path:
                assert ent in self.lookup_path(REMOTE, ent[REMOTE].path), ("%s remote path not indexed" % ent)
            if ent[LOCAL].oid is not None:
                assert ent is self.lookup_oid(LOCAL, ent[LOCAL].oid), ("%s local oid not indexed" % ent)
            if ent[REMOTE].oid is not None:
                assert ent is self.lookup_oid(REMOTE, ent[REMOTE].oid), ("%s local oid not indexed" % ent)

            if ent[LOCAL].changed or ent[REMOTE].changed:
                if ent not in self._changeset:
                    assert False, ("changeset missing %s" % ent)

    def get_all(self, discarded=False) -> Set['SyncEntry']:
        ents = set()
        for ent in self._oids[LOCAL].values():
            assert ent
            if (ent.is_discarded or ent.is_conflicted) and not discarded:
                continue
            ents.add(ent)

        for ent in self._oids[REMOTE].values():
            assert ent
            if (ent.is_discarded or ent.is_conflicted) and not discarded:
                continue
            ents.add(ent)

        return ents

    def entry_count(self):
        return len(self.get_all())

    def split(self, ent):
        log.debug("splitting %s", ent)
        defer = REMOTE
        replace = LOCAL

        defer_ent = ent

        replace_ent = SyncEntry(self, ent[replace].otype)
        assert ent[replace].oid
        replace_ent[replace] = ent[replace]
        assert replace_ent[replace].oid

        if ent[replace].oid is not None:
            assert replace_ent in self.get_all()

        if defer_ent[replace].path:
            assert self.lookup_path(replace, defer_ent[replace].path)

        defer_ent[replace].clear()

        assert replace_ent[replace].oid
        assert replace_ent in self.get_all()

        self.mark_changed(replace, replace_ent)
        self.mark_changed(defer, defer_ent)

        assert replace_ent[replace].oid

        # we aren't synced
        replace_ent[replace].sync_path = None
        defer_ent[defer].sync_path = None

        log.debug("split: %s", defer_ent)
        log.debug("split: %s", replace_ent)

        self.pretty_log_state_table_diffs(header="SPLIT")

        assert replace_ent[replace].oid

        return defer_ent, defer, replace_ent, replace

    def unconditionally_get_no_info(self, ent, side):
        if ent[side].exists == UNKNOWN:
            if not self.providers[side].oid_is_path:
                # missing oid from oid provider == trashed
                ent[side].exists = TRASHED

        if ent[side].exists == LIKELY_TRASHED:
            if self.providers[side].oid_is_path:
                # note: oid_is_path providers are not supposed to do this
                # it's possible we are wrong, and there's a trashed event arriving soon
                log.info("possible out of order events received for trashed/exists: %s", ent)
            ent[side].exists = TRASHED

        if ent[side].exists != TRASHED:
            # we haven't gotten a trashed event yet
            ent[side].exists = MISSING if self.providers[side].oid_is_path else TRASHED

        if ent[side].exists == TRASHED:
            ent[side].size = None
            ent[side].mtime = None

    def unconditionally_get_latest(self, ent, side):
        if ent[side].oid is None:
            if ent[side].exists not in (TRASHED, MISSING):
                ent[side].exists = UNKNOWN
            return

        info: OInfo = self.providers[side].info_oid(ent[side].oid, use_cache=False)

        if not info:
            self.unconditionally_get_no_info(ent, side)
            return

        if ent[side].hash != info.hash:
            ent[side].hash = info.hash
            if ent.ignored == IgnoreReason.NONE and not ent[side].changed:
                ent[side].changed = time.time()

        # if it's corrupt, then "exists" won't actually change to the new value
        # set the exists after setting the hash, since that can clear the corrupt flag
        ent[side].exists = EXISTS

        ent[side].otype = info.otype

        if ent[side].otype == FILE:
            if ent[side].hash is None:
                ent[side].hash = self.providers[side].hash_oid(ent[side].oid)

            if ent[side].exists == EXISTS:
                if ent[side].hash is None:
                    log.warning("Cannot sync %s, since hash is None", ent[side])

        new_path = self.providers[side].normalize_path_separators(info.path)
        if ent[side].path != new_path:
            ent[side].path = new_path
            if ent.ignored == IgnoreReason.NONE and not ent[side].changed:
                ent[side].changed = time.time()

        ent[side].size = info.size
        ent[side].mtime = info.mtime

    def get_state_lookup(self, side: int) -> 'SyncStateLookup':
        return SyncStateLookup(self, side)


class SyncStateLookup:
    """
    Limited read-only SyncState interface
    """

    def __init__(self, state: 'SyncState', side: int):
        self.__state = state
        self.__side = side

    def get_path(self, oid: str) -> Optional[str]:
        state = self.__state.lookup_oid(self.__side, oid)
        return state[self.__side].path if state else None
