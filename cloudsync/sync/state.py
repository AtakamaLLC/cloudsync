import copy
import json
import logging
import time
import traceback
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Tuple, Any, List, Dict, Set
from typing import Union

from cloudsync.types import DIRECTORY, FILE, NOTKNOWN
from cloudsync.types import OType
from .util import debug_sig

log = logging.getLogger(__name__)

__all__ = ['SyncState', 'SyncEntry', 'Storage', 'LOCAL', 'REMOTE', 'FILE', 'DIRECTORY']

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
class SideState(Reprable):                          # pylint: disable=too-few-public-methods, too-many-instance-attributes
    def __init__(self, side: int, otype: OType):
        self.side: int = side                            # just for assertions
        self.otype: OType = otype
        self.hash: Optional[bytes] = None           # hash at provider
        # time of last change (we maintain this)
        self.changed: Optional[float] = None
        self.sync_hash: Optional[bytes] = None      # hash at last sync
        self.sync_path: Optional[str] = None        # path at last sync
        self.path: Optional[str] = None             # path at provider
        self.oid: Optional[str] = None              # oid at provider
        self._exists: Exists = UNKNOWN               # exists at provider
        self.temp_file: Optional[str] = None

    @property
    def exists(self):
        return self._exists

    # allow traditional sets of ternary
    @exists.setter
    def exists(self, val: Union[bool, Exists]):
        if val is False:
            val = TRASHED
        if val is True:
            val = EXISTS
        if val is None:
            val = UNKNOWN

        if type(val) != Exists:
            raise ValueError("use enum for exists")

        self._exists = val


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
class SyncEntry(Reprable):
    def __init__(self, otype: OType, storage_init: Optional[Tuple[Any, bytes]] = None):
        super().__init__()
        self.__states: List[SideState] = [SideState(0, otype), SideState(1, otype)]
        self.discarded: str = ""
        self.storage_id: Any = None
        self.dirty: bool = True
        self.punted: int = 0

        if storage_init is not None:
            self.storage_id = storage_init[0]
            self.deserialize(storage_init)
            self.dirty = False

    def serialize(self) -> bytes:
        """converts SyncEntry into a json str"""
        def side_state_to_dict(side_state: SideState) -> dict:
            ret = dict()
            ret['otype'] = side_state.otype.value
            ret['side'] = side_state.side
            ret['hash'] = side_state.hash.hex() if isinstance(
                side_state.hash, bytes) else None
            ret['changed'] = side_state.changed
            ret['sync_hash'] = side_state.sync_hash.hex() if isinstance(
                side_state.sync_hash, bytes) else None
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
        return json.dumps(ser).encode('utf-8')

    def deserialize(self, storage_init: Tuple[Any, bytes]):
        """loads the values in the serialization dict into self"""
        def dict_to_side_state(side, side_dict: dict) -> SideState:
            otype = OType(side_dict['otype'])
            side_state = SideState(side, otype)
            side_state.side = side_dict['side']
            side_state.hash = bytes.fromhex(
                side_dict['hash']) if side_dict['hash'] else None
            side_state.changed = side_dict['changed']
            side_state.sync_hash = bytes.fromhex(
                side_dict['sync_hash']) if side_dict['sync_hash'] else None
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
        self.discarded = ser['discarded']

    def __getitem__(self, i):
        return self.__states[i]

    def __setitem__(self, i, val):
        assert type(val) is SideState
        assert val.side is None or val.side == i
        self.__states[i] = val
        self.dirty = True

    def hash_conflict(self):
        if self[0].hash and self[1].hash:
            return self[0].hash != self[0].sync_hash and self[1].hash != self[1].sync_hash
        return False

    def is_path_change(self, changed):
        return self[changed].path != self[changed].sync_path

    def is_creation(self, changed):
        return not self[changed].sync_path and self[changed].path

    def discard(self):
        self.discarded = ''.join(traceback.format_stack())
        self.dirty = True

    @staticmethod
    def prettyheaders():
        ret = "%3s %3s %3s %6s %20s %6s %22s -- %6s %20s %6s %22s %s" % (
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
        )
        return ret

    def pretty(self, fixed=True, use_sigs=True):
        if self.discarded:
            return "DISCARDED"

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
        lhma = abbrev_bool(self[LOCAL].sync_hash !=
                           self[LOCAL].hash, ("H", "=", "?"))
        rhma = abbrev_bool(self[REMOTE].sync_hash !=
                           self[REMOTE].hash, ("H", "=", "?"))

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
                            self[REMOTE].oid), str(self[REMOTE].sync_path) + ":" + lexv + ":" + lhma),
                        self.punted))

        ret = "%3s %3s %3s %6s %20s %6s %22s -- %6s %20s %6s %22s %s" % (
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
            self.punted or ""
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
        self.punted += 1


class SyncState:
    def __init__(self, storage: Optional[Storage] = None, tag: Optional[str] = None):
        self._oids = ({}, {})
        self._paths = ({}, {})
        self._changeset = set()
        self._storage: Optional[Storage] = storage
        self._tag = tag
        self.cursor_id = dict()
        if self._storage:
            storage_dict = self._storage.read_all(tag)
            for eid, ent_ser in storage_dict.items():
                ent = SyncEntry(None, (eid, ent_ser))
                for side in [LOCAL, REMOTE]:
                    path, oid = ent[side].path, ent[side].oid
                    if path not in self._paths[side]:
                        self._paths[side][path] = {}
                    self._paths[side][path][oid] = ent
                    self._oids[side][oid] = ent

    def _change_path(self, side, ent, path, provider):
        assert type(ent) is SyncEntry
        assert ent[side].oid

        prior_ent = ent
        prior_path = ent[side].path

        if prior_path:
            if prior_path in self._paths[side]:
                if prior_path == path and ent[side].oid in self._paths[side][prior_path]:
                    return
                prior_ent = self._paths[side][prior_path].pop(ent[side].oid, None)

            if not self._paths[side][prior_path]:
                del self._paths[side][prior_path]

        if path:
            if path not in self._paths[side]:
                self._paths[side][path] = {}
            self._paths[side][path][ent[side].oid] = ent
            ent[side].path = path
            ent.dirty = True

        if prior_ent and prior_ent in self._changeset and prior_ent is not ent:
            log.debug("alter changeset")
            self._changeset.remove(prior_ent)
            self._changeset.add(ent)

        if ent[side].otype == DIRECTORY and prior_path != path and not prior_path is None:
            # changing directory also changes child paths
            for sub in self.get_all():
                if not sub[side].path:
                    continue
                relative = provider.is_subpath(prior_path, sub[side].path)
                if relative:
                    new_path = provider.join(path, relative)
                    self._change_path(side, sub, new_path, provider)
                    if provider.oid_is_path:
                        # TODO: state should not do online hits esp from event manager
                        # either
                        # a) have event manager *not* trigger this, maybe by passing none as the provider, etc
                        #    this may have knock on effects where the sync engine needs to process parent folders first
                        # b) have a special oid_from_path function that is guaranteed not to be "online"
                        #    assert not _api() called, etc.
                        new_info = provider.info_path(new_path)
                        self._change_oid(side, sub, new_info.oid)

        assert ent in self.get_all()

    def _change_oid(self, side, ent, oid):
        assert type(ent) is SyncEntry

        prior_oid = ent[side].oid
        path = ent[side].path
        log.debug("side(%s) of %s oid -> %s", side, ent, debug_sig(oid))

        other = other_side(side)
        if ent[other].path:
            assert ent in self.lookup_path(other, ent[other].path), ("%s %s path not indexed" % (other, ent))

        prior_ent = None
        if prior_oid:
            prior_ent = self._oids[side].pop(prior_oid, None)

        if oid:
            ent[side].oid = oid
            ent.dirty = True
            self._oids[side][oid] = ent
        else:
            log.debug("removed oid from index")

        other = other_side(side)
        if ent[other].path:
            assert ent in self.lookup_path(other, ent[other].path), ("%s %s path not indexed" % (other, ent))

        maybe_remove = set()
        if prior_ent and prior_ent is not ent and prior_ent in self._changeset:
            maybe_remove.add(prior_ent)
            self._changeset.add(ent)
            prior_ent = None

        if prior_oid and path and path in self._paths[side]:
            prior_ent = self._paths[side][path].pop(prior_oid, None)

        if oid and ent[side].path:
            if ent[side].path not in self._paths[side]:
                self._paths[side][ent[side].path] = {}
            self._paths[side][ent[side].path][oid] = ent

        if prior_ent and prior_ent is not ent and prior_ent in self._changeset:
            maybe_remove.add(prior_ent)

        for r in maybe_remove:
            if r in self.get_all():
                continue
            log.debug("removing %s because oid and path not in index", r)
            self._changeset.remove(r)

    def lookup_oid(self, side, oid):
        try:
            ret = self._oids[side][oid]
            if not ret.discarded:
                return ret
            return None
        except KeyError:
            return None

    def lookup_path(self, side, path):
        try:
            ret = self._paths[side][path].values()
            if ret:
                return [e for e in ret if not e.discarded]
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

    def update_entry(self, ent, side, oid, provider, *, path=None, hash=None, exists=True, changed=False, otype=None):  # pylint: disable=redefined-builtin, too-many-arguments
        if oid is not None:
            self._change_oid(side, ent, oid)

        if otype is not None:
            ent[side].otype = otype

        if otype is NOTKNOWN:
            assert not exists

        if path is not None:
            if provider is None:
                raise ValueError("Need provider info for path changes")
            self._change_path(side, ent, path, provider)

        if oid:
            assert ent in self.get_all()

        if hash is not None:
            ent[side].hash = hash
            ent.dirty = True

        if exists is not None and exists is not ent[side].exists:
            ent[side].exists = exists
            ent.dirty = True

        if changed:
            assert ent[side].path or ent[side].oid
            log.debug("add %s to changeset", ent)
            self.mark_changed(side, ent)

        if oid:
            assert ent in self.get_all()

        log.debug("updated %s", ent)

    def mark_changed(self, side, ent):
        ent[side].changed = time.time()
        self._changeset.add(ent)

    def storage_get_cursor(self, cursor_tag):
        if cursor_tag is None:
            return None
        retval = None
        if self._storage is not None:
            if cursor_tag in self.cursor_id:
                retval = self._storage.read(cursor_tag, self.cursor_id[cursor_tag])
            if not retval:
                cursors = self._storage.read_all(cursor_tag)
                for eid, cursor in cursors.items():
                    self.cursor_id[cursor_tag] = eid
                    retval = cursor
                if len(cursors) > 1:
                    log.warning("Multiple cursors found for %s", cursor_tag)
        log.debug("storage_get_cursor id=%s cursor=%s", cursor_tag, str(retval))
        return retval

    def storage_update_cursor(self, cursor_tag, cursor):
        if cursor_tag is None:
            return
        updated = 0
        if self._storage is not None:
            if cursor_tag in self.cursor_id and self.cursor_id[cursor_tag]:
                updated = self._storage.update(cursor_tag, cursor, self.cursor_id[cursor_tag])
                log.debug("storage_update_cursor cursor %s %s", cursor_tag, cursor)
            if not updated:
                self.cursor_id[cursor_tag] = self._storage.create(cursor_tag, cursor)
                log.debug("storage_update_cursor cursor %s %s", cursor_tag, cursor)

    def storage_update(self, ent: SyncEntry):
        log.debug("storage_update eid%s", ent.storage_id)
        if self._storage is not None:
            if ent.storage_id is not None:
                if ent.discarded:
                    log.debug("storage_update deleting eid%s", ent.storage_id)
                    self._storage.delete(self._tag, ent.storage_id)
                else:
                    self._storage.update(self._tag, ent.serialize(), ent.storage_id)
            else:
                if ent.discarded:
                    log.error("Entry should not be discarded. Discard happened at: %s", ent.discarded)
                    assert not ent.discarded  # always raises, due to being in this if condition
                new_id = self._storage.create(self._tag, ent.serialize())
                ent.storage_id = new_id
                log.debug("storage_update creating eid%s", ent.storage_id)
            ent.dirty = False

    def __len__(self):
        return len(self.get_all())

    def update(self, side, otype, oid, provider, path=None, hash=None, exists=True, prior_oid=None):   # pylint: disable=redefined-builtin, too-many-arguments
        log.debug("lookup %s", debug_sig(oid))
        ent = self.lookup_oid(side, oid)

        prior_ent = None
        if prior_oid and prior_oid != oid:
            prior_ent = self.lookup_oid(side, prior_oid)
            if not ent:
                ent = prior_ent
                prior_ent = None

        if ent and prior_ent:
            # oid_is_path conflict
            # the new entry has the same name as an old entry
            log.debug("rename o:%s path:%s prior:%s", debug_sig(oid), path, debug_sig(prior_oid))
            log.debug("discarding old entry in favor of new %s", prior_ent)
            ent.discard()
            ent = prior_ent

        if prior_oid and prior_oid != oid:
            # this is an oid_is_path provider
            path_ents = self.lookup_path(side, path)
            if path_ents:
                if not ent:
                    ent = path_ents[0]
                    log.debug("matched existing entry %s:%s", debug_sig(oid), path)
                elif ent is not path_ents[0]:
                    path_ents[0].discard()
                    log.debug("discarded existing entry %s:%s", debug_sig(oid), path)

        if not ent:
            log.debug("creating new entry because %s not found in %s", debug_sig(oid), side)
            ent = SyncEntry(otype)

        self.update_entry(ent, side, oid, provider, path=path, hash=hash, exists=exists, changed=True, otype=otype)

        self.storage_update(ent)

    def change(self, age):
        earlier_than = time.time() - age
        # for now just get a random one
        for puntlevel in range(3):
            for e in self._changeset:
                if not e.discarded and e.punted == puntlevel:
                    if (e[LOCAL].changed and e[LOCAL].changed <= earlier_than) \
                            or (e[REMOTE].changed and e[REMOTE].changed <= earlier_than):
                        return e

        for e in list(self._changeset):
            if e.discarded:
                self._changeset.remove(e)
            else:
                if (e[LOCAL].changed and e[LOCAL].changed <= earlier_than) \
                        or (e[REMOTE].changed and e[REMOTE].changed <= earlier_than):
                    return e

        return None

    def has_changes(self):
        return bool(self._changeset)

    def finished(self, ent):
        if ent[1].changed or ent[0].changed:
            log.info("not marking finished: %s", ent)
            return

        self._changeset.remove(ent)

        for e in self._changeset:
            e.punted = 0

    def pretty_print(self, use_sigs=True):
        ret = SyncEntry.prettyheaders() + "\n"
        for e in self.get_all():
            e: SyncEntry
            ret += e.pretty(fixed=True, use_sigs=use_sigs) + "\n"
        return ret

    def assert_index_is_correct(self):
        for ent in self._changeset:
            if not ent.discarded:
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

    def get_all(self, discarded=False) -> Set['SyncState']:
        ents = set()
        for ent in self._oids[LOCAL].values():
            assert ent
            if ent.discarded and not discarded:
                continue
            ents.add(ent)

        for ent in self._oids[REMOTE].values():
            assert ent
            if ent.discarded and not discarded:
                continue
            ents.add(ent)

        return ents

    def entry_count(self):
        return len(self.get_all())

    def split(self, ent, providers):
        log.debug("splitting %s", ent)
        defer = REMOTE
        replace = LOCAL

        defer_ent = ent

        replace_ent = SyncEntry(ent[replace].otype)
        replace_ent[replace] = copy.copy(ent[replace])       # copy in the replace state
        defer_ent[replace] = SideState(replace, ent[replace].otype)              # clear out

        # fix indexes, so the defer ent no longer has replace stuff
        self.update_entry(defer_ent, replace, oid=None,
                          path=None, exists=UNKNOWN, provider=providers[defer])
        self.update_entry(defer_ent, defer,
                          oid=defer_ent[defer].oid, changed=True, provider=providers[replace])
        # add to index
        assert replace_ent[replace].oid
        self.update_entry(
            replace_ent, replace, oid=replace_ent[replace].oid, path=replace_ent[replace].path, changed=True, provider=providers[replace])

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
