# pylint: disable=attribute-defined-outside-init, protected-access
"""
SyncEntry[SideState, SideState] is a pair of entries, indexed by oid.  The SideState class makes
extensive use of __getattr__ logic to keep indexes up to date.

There may be no need to keep them in "pairs".   This is artificial. States should probably be
altered to independent, and not paired at all.
"""

import copy
import json
import logging
import time
import traceback
from threading import RLock
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Tuple, Any, List, Dict, Set, cast, TYPE_CHECKING, Callable, Generator

from typing import Union
from pystrict import strict

from cloudsync.types import DIRECTORY, FILE, NOTKNOWN
from cloudsync.types import OType
from cloudsync.scramble import scramble
from cloudsync.log import TRACE
from .util import debug_sig
if TYPE_CHECKING:
    from cloudsync import Provider


log = logging.getLogger(__name__)

__all__ = ['SyncState', 'SyncEntry', 'Storage', 'LOCAL', 'REMOTE', 'FILE', 'DIRECTORY', 'UNKNOWN']

# adds a repr to some classes


class Reprable:                                     # pylint: disable=too-few-public-methods
    def __repr__(self):
        return self.__class__.__name__ + ":" + debug_sig(id(self)) + str(self.__dict__)

# safe ternary, don't allow traditional comparisons


class Exists(Enum):
    UNKNOWN = None
    EXISTS = True
    TRASHED = False

    def __bool__(self):
        raise ValueError("never bool enums")


UNKNOWN = Exists.UNKNOWN
EXISTS = Exists.EXISTS
TRASHED = Exists.TRASHED


# state of a single object
@strict         # pylint: disable=too-many-instance-attributes
class SideState(Reprable):
    def __init__(self, parent: 'SyncEntry', side: int, otype: Optional[OType]):
        self._parent = parent
        self._side: int = side                            # just for assertions
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
        self._temp_file: Optional[str] = None
        self.hash: Optional[bytes]
        self.sync_hash: Optional[bytes]

    def __getattr__(self, k):
        if k[0] != "_":
            return getattr(self, "_" + k)
        raise AttributeError("%s not in SideState" % k)

    def __setattr__(self, k, v):
        if k[0] == "_":
            object.__setattr__(self, k, v)
            return

        self._parent.updated(self._side, k, v)

        if k == "exists":
            self._set_exists(v)
        else:
            object.__setattr__(self, "_" + k, v)

    def _set_exists(self, val: Union[bool, Exists]):
        if val is False:
            xval = TRASHED
        elif val is True:
            xval = EXISTS
        elif val is None:
            xval = UNKNOWN
        else:
            xval = cast(Exists, val)

        if type(xval) != Exists:
            raise ValueError("use enum for exists")

        self._exists = xval
        self._parent.updated(self._side, "exists", xval)

    def set_aged(self):
        # setting to an old mtime marks this as fully aged
        self.changed = 1

    def clear(self):
        self.parent[1-self.side].sync_path = None
        self.parent[1-self.side].sync_hash = None
        self.exists = UNKNOWN
        self.changed = None
        self.hash = None
        self.sync_hash = None
        self.sync_path = None
        self.path = None
        self.oid = None


# these are not really local or remote
# but it's easier to reason about using these labels
LOCAL = 0
REMOTE = 1


def other_side(index):
    return 1-index


class Storage(ABC):
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
        """ take a serialization str, upsert it in sqlite, return the row id of the row as a persistence id"""
        ...

    @abstractmethod
    def read_all(self, tag: str) -> Dict[Any, bytes]:
        """yield all the serialized strings in a generator"""
        ...

    @abstractmethod
    def read(self, tag: str, eid: Any) -> Optional[bytes]:
        """return one serialized string or None"""
        ...


# single entry in the syncs state collection
@strict         # pylint: disable=too-many-instance-attributes
class SyncEntry(Reprable):
    def __init__(self, parent: 'SyncState', otype: Optional[OType], storage_init: Optional[Tuple[Any, bytes]] = None):
        super().__init__()
        assert otype is not None or storage_init
        self.__states: List[SideState] = [SideState(self, 0, otype), SideState(self, 1, otype)]
        self._discarded: str = ""
        self._conflicted: bool = False
        self._storage_id: Any = None
        self._dirty: bool = True
        self._punted: int = 0
        self._parent = parent

        if storage_init is not None:
            self._storage_id = storage_init[0]
            self.deserialize(storage_init)
            self._dirty = False
        log.debug("new syncent %s", debug_sig(id(self)))

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

    def updated(self, side, key, val):
        self._dirty = True
        self._parent.updated(self, side, key, val)

    def serialize(self) -> bytes:
        """converts SyncEntry into a json str"""
        def side_state_to_dict(side_state: SideState) -> dict:
            ret = dict()
            ret['otype'] = side_state.otype.value
            ret['side'] = side_state.side
            ret['hash'] = side_state.hash.hex() if isinstance(side_state.hash, bytes) else None
            ret['changed'] = side_state.changed
            ret['sync_hash'] = side_state.sync_hash.hex() if isinstance(side_state.sync_hash, bytes) else None
            ret['path'] = side_state.path
            ret['sync_path'] = side_state.sync_path
            ret['oid'] = side_state.oid
            ret['exists'] = side_state.exists.value
            ret['temp_file'] = side_state.temp_file
            # storage_id does not get serialized, it always comes WITH a serialization when deserializing
            return ret

        ser = dict()
        ser['side0'] = side_state_to_dict(self.__states[0])
        ser['side1'] = side_state_to_dict(self.__states[1])
        ser['discarded'] = self.discarded
        ser['conflicted'] = self.conflicted
        return json.dumps(ser).encode('utf-8')

    def deserialize(self, storage_init: Tuple[Any, bytes]):
        """loads the values in the serialization dict into self"""
        def dict_to_side_state(side, side_dict: dict) -> SideState:
            otype = OType(side_dict['otype'])
            side_state = SideState(self, side, otype)
            side_state.side = side_dict['side']
            side_state.hash = bytes.fromhex(side_dict['hash']) if side_dict['hash'] else None
            side_state.changed = side_dict['changed']
            side_state.sync_hash = bytes.fromhex(side_dict['sync_hash']) if side_dict['sync_hash'] else None
            side_state.sync_path = side_dict['sync_path']
            side_state.path = side_dict['path']
            side_state.oid = side_dict['oid']
            side_state.exists = side_dict['exists']
            side_state.temp_file = side_dict['temp_file']
            return side_state

        self.storage_id = storage_init[0]
        ser: dict = json.loads(storage_init[1].decode('utf-8'))
        self.__states = [dict_to_side_state(0, ser['side0']),
                         dict_to_side_state(1, ser['side1'])]
        self.discarded = ser.get('discarded', "")
        self.conflicted = ser.get('conflicted', False)

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
        if self[0].hash and self[1].hash:
            return self[0].hash != self[0].sync_hash and self[1].hash != self[1].sync_hash
        return False

    def is_path_change(self, changed):
        return self[changed].path != self[changed].sync_path

    def is_creation(self, changed):
        return not self[changed].sync_path and self[changed].path

    def is_rename(self, changed):
        return (self[changed].sync_path and self[changed].path
                and self[changed].sync_path != self[changed].path)

    def needs_sync(self):
        for i in (LOCAL, REMOTE):
            if not self[i].changed:
                continue
            if self[i].path != self[i].sync_path:
                return True
            if self[i].hash != self[i].sync_hash:
                return True
        if self[LOCAL].exists != self[REMOTE].exists:
            return True
        return False

    def discard(self):
        self.discarded = ''.join(traceback.format_stack())

    def conflict(self):
        self.conflicted = True

    def unconflict(self):
        self.conflicted = False

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
            "Punt",  # self.punted or ""
            "Conflict",  # self.conflicted or ""
        )
        return ret

    def pretty(self, fixed=True, use_sigs=True):
        ret = ""
        if self.discarded:
            ret = "DISCARDED"

        def secs(t):
            if t:
                return str(round(t % 300, 3)).replace(".", "")
            else:
                return 0

        def abbrev_bool(b, tup=('T', 'F', '?')):
            idx = 1-int(bool(b))
            if b is None:
                idx = 2
            return tup[idx]

        lexv = abbrev_bool(self[LOCAL].exists.value, ("E", "X", "?"))
        rexv = abbrev_bool(self[REMOTE].exists.value, ("E", "X", "?"))
        lhma = abbrev_bool(self[LOCAL].hash and self[LOCAL].sync_hash !=
                           self[LOCAL].hash, ("H", "=", "?"))
        rhma = abbrev_bool(self[REMOTE].hash and self[REMOTE].sync_hash !=
                           self[REMOTE].hash, ("H", "=", "?"))

        _sig: Callable[[Any], Any]
        if use_sigs:
            _sig = debug_sig
        else:
            _sig = lambda a: a

        local_otype = self[LOCAL].otype.value if self[LOCAL].otype else '?'
        remote_otype = self[REMOTE].otype.value if self[REMOTE].otype else '?'

        if local_otype != remote_otype:
            otype = local_otype[0] + "-" + remote_otype[0]
        else:
            otype = local_otype

        if not fixed:
            return str((_sig(id(self)), otype,
                        (secs(self[LOCAL].changed), self[LOCAL].path, _sig(
                            self[LOCAL].oid), str(self[LOCAL].sync_path) + ":" + lexv + ":" + lhma),
                        (secs(self[REMOTE].changed), self[REMOTE].path, _sig(
                            self[REMOTE].oid), str(self[REMOTE].sync_path) + ":" + rexv + ":" + rhma),
                        self._punted,
                        self._conflicted or bool(self._discarded)))

        ret += "%3s %3s %3s %6s %20s %6s %22s -- %6s %20s %6s %22s %s %s" % (
            _sig(id(self)),
            _sig(self.storage_id),
            otype[:3],
            secs(self[LOCAL].changed),
            self[LOCAL].path,
            _sig(self[LOCAL].oid),
            str(self[LOCAL].sync_path) + ":" + lexv + ":" + lhma,
            secs(self[REMOTE].changed),
            self[REMOTE].path,
            _sig(self[REMOTE].oid),
            str(self[REMOTE].sync_path) + ":" + rexv + ":" + rhma,
            self._punted or "",
            self._conflicted or "",
        )

        return ret

    def __str__(self):
        return self.pretty(fixed=False)

    def store(self, tag: str, storage: Storage):
        if not self.storage_id:
            self.storage_id = storage.create(tag, self.serialize())
        else:
            storage.update(tag, self.serialize(), self.storage_id)

    def punt(self):
        # do this one later
        # TODO provide help for making sure that we don't punt too many times
        self.punted += 1                    # pylint: disable=no-member
        if self[LOCAL].changed:
            self[LOCAL].changed += self._parent._punt_secs[LOCAL]
        if self[REMOTE].changed:
            self[REMOTE].changed = self._parent._punt_secs[REMOTE]

    def get_latest(self):
        for side in (LOCAL, REMOTE):
            if self[side]._changed and self[side]._changed > self[side]._last_gotten:
                self._parent.unconditionally_get_latest(self, side)
                self[side]._last_gotten = self[side]._changed

    def is_latest(self) -> bool:
        for side in (LOCAL, REMOTE):
            if self[side]._changed and self[side]._changed > self[side]._last_gotten:
                return False
        return True

@strict
class SyncState:  # pylint: disable=too-many-instance-attributes
    def __init__(self,
                 providers: Tuple['Provider', 'Provider'],
                 storage: Optional[Storage] = None,
                 tag: Optional[str] = None,
                 shuffle: bool = False):
        self._oids: Tuple[Dict[Any, SyncEntry], Dict[Any, SyncEntry]] = ({}, {})
        self._paths: Tuple[Dict[str, Dict[Any, SyncEntry]], Dict[str, Dict[Any, SyncEntry]]] = ({}, {})
        self._changeset: Set[SyncEntry] = set()
        self._storage: Optional[Storage] = storage
        self._tag = tag
        self.providers = providers
        self._punt_secs = (providers[0].default_sleep/10, providers[1].default_sleep/10)
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
                ent = SyncEntry(self, None, (eid, ent_ser))
                for side in [LOCAL, REMOTE]:
                    path, oid = ent[side].path, ent[side].oid
                    if path not in self._paths[side]:
                        self._paths[side][path] = {}
                    self._paths[side][path][oid] = ent
                    self._oids[side][oid] = ent
                    if ent[side].changed:
                        self._changeset.add(ent)
            self._loading = False

    def updated(self, ent, side, key, val):
        if self._loading:
            return

        assert key

        if key == "path":
            self._change_path(side, ent, val, self.providers[side])
        elif key == "oid":
            self._change_oid(side, ent, val)
        elif key == "discarded" and val:
            ent[LOCAL]._changed = False
            ent[REMOTE]._changed = False
            self._changeset.discard(ent)
        elif key == "changed":
            if val or ent[other_side(side)].changed:
                self._changeset.add(ent)
            else:
                self._changeset.discard(ent)

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

    def _update_kids(self, ent, side, prior_path, path, provider):
        if ent[side].otype == DIRECTORY and prior_path != path and not prior_path is None:
            # changing directory also changes child paths
            for sub, relative in self.get_kids(prior_path, side):
                new_path = provider.join(path, relative)
                sub[side].path = new_path
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

    def _change_oid(self, side, ent, oid):
        assert type(ent) is SyncEntry

        prior_oid = ent[side].oid

        prior_ent = None
        if prior_oid:
            prior_ent = self._oids[side].pop(prior_oid, None)

            if prior_ent:
                if prior_ent[side].path:
                    prior_path = prior_ent[side].path
                    if prior_path in self._paths[side]:
                        self._paths[side][prior_path].pop(prior_oid, None)
                        if not self._paths[side][prior_path]:
                            del self._paths[side][prior_path]

                if prior_ent is not ent:
                    # no longer indexed by oid, also clear change bit
                    prior_ent[side].oid = None
                    if prior_ent[side].exists != TRASHED:
                        prior_ent[side].changed = False

        if oid:
            ent[side]._oid = oid
            self._oids[side][oid] = ent

            assert self.lookup_oid(side, oid) is ent

        if oid and ent[side].path:
            if ent[side].path not in self._paths[side]:
                self._paths[side][ent[side].path] = {}
            self._paths[side][ent[side].path][oid] = ent

        if oid:
            assert self.lookup_oid(side, oid) is ent

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
            ret = self._paths[side][path].values()
            if ret:
                return [e for e in ret if stale or (not e.discarded and not e.conflicted)]
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

    def update_entry(self, ent, side, oid, *, path=None, hash=None, exists=True, changed=False, otype=None):  # pylint: disable=redefined-builtin, too-many-arguments
        assert ent

        if oid is not None:
            if ent.discarded:
                if self.providers[side].oid_is_path:
                    if path:
                        if otype:
                            log.log(TRACE, "dropping old entry %s, and making new", ent)
                            ent = SyncEntry(self, otype)

            ent[side].oid = oid

            if oid and not ent.discarded and not ent.conflicted:
                if ent not in self.get_all():
                    assert False, "Index is fucked %s" % ent[side]

        if otype is not None and otype != ent[side].otype:
            ent[side].otype = otype

        assert otype is not NOTKNOWN or not exists

        if path is not None and path != ent[side].path:
            ent[side].path = path

        if hash is not None and hash != ent[side].hash:
            ent[side].hash = hash

        if exists is not None and exists is not ent[side].exists:
            ent[side].exists = exists

        if changed:
            assert ent[side].path or ent[side].oid
            log.log(TRACE, "add %s to changeset", ent)
            self._mark_changed(side, ent)

        log.log(TRACE, "updated %s", ent)

    def _mark_changed(self, side, ent):
        ent[side].changed = time.time()
        assert ent in self._changeset

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

    def storage_update(self, ent: SyncEntry):
        if self._tag is None:
            return

        log.log(TRACE, "storage_update eid%s", ent.storage_id)
        if self._storage is not None:
            if ent.storage_id is not None:
                self._storage.update(cast(str, self._tag), ent.serialize(), ent.storage_id)
            else:
                new_id = self._storage.create(cast(str, self._tag), ent.serialize())
                ent.storage_id = new_id
                log.debug("storage_update creating eid%s", ent.storage_id)
            ent.dirty = False

    def __len__(self):
        return len(self.get_all())

    def update(self, side, otype, oid, path=None, hash=None, exists=True, prior_oid=None):   # pylint: disable=redefined-builtin, too-many-arguments
        log.log(TRACE, "lookup %s", debug_sig(oid))
        ent: SyncEntry = self.lookup_oid(side, oid)

        prior_ent = None

        if prior_oid and prior_oid != oid:
            prior_ent = self.lookup_oid(side, prior_oid)
            if prior_ent and not prior_ent.discarded:
                if ent and ent[side].exists == TRASHED and ent[side].changed and not ent.discarded:
                    ent[side].oid = None  # avoid having duplicate oids, and avoid discarding a changed entry
                ent = prior_ent
                prior_ent = None

            if not ent:
                # this is an oid_is_path provider
                path_ents = self.lookup_path(side, path, stale=True)
                for path_ent in path_ents:
                    ent = path_ent
                    ent.discarded = False
                    log.debug("matched existing entry %s:%s", debug_sig(oid), path)

        if not ent:
            log.debug("creating new entry because %s not found in %s", debug_sig(oid), side)
            ent = SyncEntry(self, otype)

        self.update_entry(ent, side, oid, path=path, hash=hash, exists=exists, changed=True, otype=otype)

        self.storage_update(ent)

    def change(self, age):
        if not self._changeset:
            return None

        if self.shuffle:
            changes = scramble(self._changeset, 10)
        else:
            changes = sorted(self._changeset, key=lambda a: max(a[LOCAL].changed or 0, a[REMOTE].changed or 0))

        earlier_than = time.time() - age
        for puntlevel in range(3):
            for e in changes:
                if not e.discarded and e.punted == puntlevel:
                    if (e[LOCAL].changed and e[LOCAL].changed <= earlier_than) \
                            or (e[REMOTE].changed and e[REMOTE].changed <= earlier_than):
                        return e

        ret = None
        for e in self._changeset:
            if (e[LOCAL].changed and e[LOCAL].changed <= earlier_than) \
                    or (e[REMOTE].changed and e[REMOTE].changed <= earlier_than):
                ret = e

        return ret

    def finished(self, ent):
        if ent[1].changed or ent[0].changed:
            log.info("not marking finished: %s", ent)
            return

        self._changeset.discard(ent)

        for e in self._changeset:
            e.punted = 0

    def pretty_print(self, use_sigs=True):
        ret = SyncEntry.prettyheaders() + "\n"
        e: SyncEntry
        for e in self.get_all(discarded=True):
            # allow conflicted to be printed
            if e.discarded:
                continue
            ret += e.pretty(fixed=True, use_sigs=use_sigs) + "\n"
        return ret

    def assert_index_is_correct(self):
        for ent in self._changeset:
            if not ent.discarded and not ent.conflicted:
                assert ent in self.get_all(), ("%s in changeset, not in index" % ent)

        for ent in self.get_all():
            assert ent

            if ent[LOCAL].path:
                assert ent in self.lookup_path(LOCAL, ent[LOCAL].path), ("%s local path not indexed" % ent)
            if ent[REMOTE].path:
                assert ent in self.lookup_path(REMOTE, ent[REMOTE].path), ("%s remote path not indexed" % ent)
            if ent[LOCAL].oid:
                assert ent is self.lookup_oid(LOCAL, ent[LOCAL].oid), ("%s local oid not indexed" % ent)
            if ent[REMOTE].oid:
                assert ent is self.lookup_oid(REMOTE, ent[REMOTE].oid), ("%s local oid not indexed" % ent)

            if ent[LOCAL].changed or ent[REMOTE].changed:
                if ent not in self._changeset:
                    assert False, ("changeset missing %s" % ent)

    def get_all(self, discarded=False) -> Set['SyncEntry']:
        ents = set()
        for ent in self._oids[LOCAL].values():
            assert ent
            if (ent.discarded or ent.conflicted) and not discarded:
                continue
            ents.add(ent)

        for ent in self._oids[REMOTE].values():
            assert ent
            if (ent.discarded or ent.conflicted) and not discarded:
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

        if ent[replace].oid:
            assert replace_ent in self.get_all()

        if defer_ent[replace].path:
            assert self.lookup_path(replace, defer_ent[replace].path)

        defer_ent[replace].clear()

        assert replace_ent[replace].oid
        assert replace_ent in self.get_all()

        self._mark_changed(replace, replace_ent)
        self._mark_changed(defer, defer_ent)

        assert replace_ent[replace].oid
        # we aren't synced
        replace_ent[replace].sync_path = None
        replace_ent[replace].sync_hash = None

        # never synced
        defer_ent[defer].sync_path = None
        defer_ent[defer].sync_hash = None

        log.debug("split: %s", defer_ent)
        log.debug("split: %s", replace_ent)

        log.info("SPLIT\n%s", self.pretty_print())

        assert replace_ent[replace].oid

        self.storage_update(defer_ent)
        self.storage_update(replace_ent)

        return defer_ent, defer, replace_ent, replace


    def unconditionally_get_latest(self, ent, i):
        if not ent[i].oid:
            if ent[i].exists != TRASHED:
                ent[i].exists = UNKNOWN
            return

        info = self.providers[i].info_oid(ent[i].oid, use_cache=False)

        if not info:
            ent[i].exists = TRASHED
            return

        ent[i].exists = EXISTS
        ent[i].hash = info.hash
        ent[i].otype = info.otype

        if ent[i].otype == FILE:
            if ent[i].hash is None:
                ent[i].hash = self.providers[i].hash_oid(ent[i].oid)

            if ent[i].exists == EXISTS:
                if ent[i].hash is None:
                    log.warning("Cannot sync %s, since hash is None", ent[i])

        if ent[i].path != info.path:
            ent[i].path = info.path
            self.update_entry(ent, oid=ent[i].oid, side=i, path=info.path)
