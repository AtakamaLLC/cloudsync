# pylint: disable=too-many-lines, missing-docstring
"""
Sync manager and associated tools.
"""

import os
import logging
import tempfile
import shutil
import hashlib
import time

from typing import Tuple, Optional, Callable, TYPE_CHECKING, List, Dict, Any, cast, BinaryIO

import msgpack
from pystrict import strict

__all__ = ['SyncManager']

import cloudsync.exceptions as ex
from cloudsync.types import DIRECTORY, FILE, IgnoreReason
from cloudsync.runnable import Runnable
from cloudsync.log import TRACE
from cloudsync.utils import debug_sig
from cloudsync.notification import SourceEnum, Notification, NotificationType
from cloudsync.types import LOCAL, REMOTE
from cloudsync import Event
from .state import SyncState, SyncEntry, SideState, MISSING, TRASHED, EXISTS, UNKNOWN

if TYPE_CHECKING:
    from cloudsync.provider import Provider
    from cloudsync.notification import NotificationManager

log = logging.getLogger(__name__)

FINISHED = 1
PUNT = 0
REQUEUE = -1


def other_side(index):
    return 1-index


@strict                         # pylint: disable=too-many-instance-attributes
class ResolveFile():
    """
    File-like handed to caller when conflicts need resolving.

    Args:
        info: The side state that this instance holds a file for
        provider: The provider for the file
    """
    def __init__(self, info: SideState, provider: 'Provider'):
        self.info = info
        self.provider = provider
        self.path = info.path
        self.side = info.side
        self.hash = info.hash
        self.sync_hash = info.sync_hash
        self.otype = info.otype
        self.__temp_file = info.temp_file
        if self.otype == FILE:
            assert info.temp_file
        self.__fh: BinaryIO = None
        self.__len: int = None

    def download(self) -> str:
        """
        Downloads the conflicted file in question to a temp file.

        Returns:
            Full path to the temp file
        """
        if not os.path.exists(self.__temp_file):
            try:
                with open(self.__temp_file + ".tmp", "wb") as f:
                    log.debug("download %s %s", self.path, self.info.oid)
                    self.provider.download(self.info.oid, f)
                os.rename(self.__temp_file + ".tmp", self.__temp_file)
            except Exception as e:
                log.warning("error downloading %s", e)
                try:
                    os.unlink(self.__temp_file)
                except FileNotFoundError:
                    pass
                raise
        else:
            log.debug("using existing temp %s", self.path)
        return self.__temp_file

    @property
    def fh(self):
        """Readable file handle for contents"""
        if not self.__fh:
            self.download()  # NOOP if it was already downloaded
            self.__fh = open(self.__temp_file, "rb")
            log.debug("ResolveFile opening temp file %s for real file %s", self.__temp_file, self.path)
        return self.__fh

    def read(self, *a):
        return self.fh.read(*a)

    def write(self, buf):
        raise NotImplementedError()

    def close(self):
        # don't use self.fh, use self.__fh. No need to download and open it, just to close it
        if self.__fh:
            log.debug("ResolveFile closing temp file %s for real file %s", self.__temp_file, self.path)
            self.__fh.close()

    def seek(self, *a):
        return self.fh.seek(*a)

    def tell(self):
        return self.fh.tell()

    def __len__(self):
        """This is for requests_toolbox, which apparently requires it."""
        if self.__len is None:
            ptr = self.fh.tell()
            self.fh.seek(0, os.SEEK_END)
            self.__len = self.fh.tell()
            self.fh.seek(ptr)
        return self.__len


@strict     # pylint: disable=too-many-public-methods, too-many-instance-attributes
class SyncManager(Runnable):
    """
    Watches the provided state for changes and copies files between providers

    Args:
        state: current state
        providers: pair of providers
        translate: a callable that converts paths between providers
        resolve_conflict: a callable that is passed two `ResolveFile` instances
        notification_manager: and instance of NotificationManager
        sleep: a tuple of seconds to sleep
    """
    def __init__(self, state: SyncState,                        # pylint: disable=too-many-arguments
                 providers: Tuple['Provider', 'Provider'],
                 translate: Callable,
                 resolve_conflict: Callable,
                 notification_manager: Optional['NotificationManager'] = None,
                 sleep: Optional[Tuple[float, float]] = None,
                 root_paths: Optional[Tuple[str, str]] = None,
                 root_oids: Optional[Tuple[str, str]] = None):
        self.state: SyncState = state
        self.providers: Tuple['Provider', 'Provider'] = providers
        self.__translate = translate
        self._resolve_conflict = resolve_conflict
        self.tempdir = tempfile.mkdtemp(suffix=".cloudsync")
        self.__nmgr = notification_manager
        self._root_oids: List[str] = list(root_oids) if root_oids else [None, None]
        self._root_paths: List[str] = list(root_paths) if root_paths else [None, None]
        if not sleep:
            # these are the event sleeps, but really we need more info than this
            sleep = (self.providers[LOCAL].default_sleep, self.providers[REMOTE].default_sleep)

        self.sleep = sleep

        ####

        max_sleep = max(sleep)                    # on sync fail, use the worst time for backoff
        self.aging = max_sleep / 5                # how long before even trying to sync
        self.min_backoff = max_sleep / 10.0       # event sleep of 15 seconds == 1.5 second backoff on failures
        self.max_backoff = max_sleep * 10.0       # escalating up to a 3 minute wait time
        self.mult_backoff = 2
        assert len(self.providers) == 2

    def set_resolver(self, resolver):
        self._resolve_conflict = resolver

    def do(self):
        need_to_sleep = True
        something_got_done = True
        with self.state.lock:
            sync: SyncEntry = self.state.change(self.aging)
            if sync:
                need_to_sleep = False
                try:
                    something_got_done = self.sync(sync)
                    self.state.storage_commit()
                except (ex.CloudTemporaryError, ex.CloudDisconnectedError, ex.CloudOutOfSpaceError, ex.CloudTokenError, ex.CloudNamespaceError) as e:
                    if self.__nmgr:
                        self.__nmgr.notify_from_exception(SourceEnum.SYNC, e)
                    log.warning(
                        "error %s[%s] while processing %s, %i", type(e), e, sync, sync.priority)
                    sync.punt()
                    # do we want to self.state.storage_commit() here?
                    self.backoff()
                except Exception as e:
                    # TODO: notify_from_exception
                    log.exception(
                        "exception %s[%s] while processing %s, %i", type(e), e, sync, sync.priority)
                    sync.punt()
                    self.state.storage_commit()
                    self.backoff()

        if need_to_sleep:
            time.sleep(self.aging)

        if not something_got_done:
            # don't clear the backoff flag if all we did was punt
            self.nothing_happened()

    def done(self):
        log.info("cleanup %s", self.tempdir)
        try:
            shutil.rmtree(self.tempdir)
        except FileNotFoundError:
            pass

    def translate(self, side, path):
        if path:
            return self.__translate(side, path)
        else:
            return None

    @property
    def busy(self):
        return self.state.changeset_len

    def change_count(self, side: Optional[int] = None, unverified: bool = False):
        """Show the number of changes for UX purposes."""
        count = 0

        sides: Tuple[int, ...]
        if side is None:
            sides = (LOCAL, REMOTE)
        else:
            sides = (side, )

        if unverified:
            return self.state.changeset_len

        for e in self.state.changes:
            for i in sides:
                if e[i].path and e[i].changed:
                    # we check 2 things..
                    # if the file translates and the file has hash changes (create/upload needed)
                    # metadata sync changes aren't relevant for visual display
                    translated_path = self.translate(other_side(i), e[i].path)
                    if translated_path:
                        if e[i].sync_hash != e[i].hash:
                            count += 1
                            # never double-count a single entry
                            # if both sides have changed - it's one sync
                            break

        return count

    def path_conflict(self, ent):
        """
        Boolean true if there is a naming conflict
        """
        # both are synced
        have_paths = ent[0].path and ent[1].path
        if not have_paths:
            return False

        # returning False here if one side hasn't changed breaks test_rename_conflict_and_irrelevant

        are_synced = ((ent[0].sync_hash and ent[1].sync_hash)
                      or (ent[0].otype == DIRECTORY and ent[1].otype == DIRECTORY)) \
                      and ent[0].sync_path and ent[1].sync_path
        if not are_synced:
            return False

        both_exist = ent[0].exists == EXISTS and ent[1].exists == EXISTS

        if not both_exist:
            return False

        translated_path = self.translate(1, ent[0].path)
        if ent[1].path == translated_path:
            return False

        return not self.providers[0].paths_match(ent[0].path, ent[0].sync_path, for_display=True) and \
            not self.providers[1].paths_match(ent[1].path, ent[1].sync_path, for_display=True) and \
            not ent.is_temp_rename

    def check_revivify(self, sync: SyncEntry):
        """
        Revives a sync entrty if it was discarded, but is now relevant, because the new translated_path is relevant
        """
        if sync.is_discarded:
            for i in (LOCAL, REMOTE):
                changed = i
                synced = other_side(i)
                se = sync[changed]
                if not se.changed or se.sync_path or not se.oid or sync.is_conflicted:
                    continue
                looked_up_sync = self.state.lookup_oid(changed, sync[changed].oid)
                if looked_up_sync and looked_up_sync != sync:
                    continue
                provider_info = self.providers[changed].info_oid(sync[changed].oid)
                if not provider_info:
                    continue
                provider_path = provider_info.path
                if not provider_path:
                    continue
                translated_path = self.translate(synced, provider_path)
                if sync.is_irrelevant and translated_path:  # was irrelevant, but now is relevant
                    log.debug(">>>about to embrace %s", sync)
                    log.debug(">>>Suddenly a cloud path %s, creating", provider_path)
                    sync.ignored = IgnoreReason.NONE
                    sync[changed].sync_path = None
                    sync[changed].changed = time.time()
                    sync[synced].clear()

    def sync(self, sync: SyncEntry) -> bool:  # pylint: disable=too-many-branches,too-many-statements
        """
        Called on each changed entry.
        """
        self.check_revivify(sync)

        if sync.is_discarded:
            self.finished(LOCAL, sync)
            self.finished(REMOTE, sync)
            return True

        sync.get_latest()

        if sync.hash_conflict():
            log.debug("handle hash conflict")
            self.handle_hash_conflict(sync)
            return True

        ordered = sorted((LOCAL, REMOTE), key=lambda e: sync[e].changed or 0)

        something_got_done = False

        for side in ordered:
            if not sync[side].needs_sync():
                # if the changed side's path doesn't translate then ignore 'needs_sync' and process
                # the change anyway (likely a rename to irrelevant directory)
                # see test_cs_rename_folder_out_of_root
                if self.translate(other_side(side), sync[side].path):
                    if sync[side].changed:
                        log.debug("Sync entry marked as changed, but doesn't need sync, finishing. %s", sync)
                    sync[side].changed = 0
                    continue

            if sync[side].hash is None and sync[side].otype == FILE and sync[side].exists == EXISTS:
                log.debug("ignore:%s, side:%s", sync, side)
                # no hash for file, ignore it
                self.finished(side, sync)
                break

            if sync[side].oid is None and sync[side].exists != TRASHED:
                log.debug("ignore:%s, side:%s", sync, side)
                self.finished(side, sync)
                continue

            # if the other side changed hash, handle it first
            if sync[side].hash == sync[side].sync_hash:
                other = other_side(side)
                if sync[other].changed and sync[other].hash != sync[other].sync_hash:
                    continue

            if self.path_conflict(sync):
                my_name = sync[side].path
                their_name = sync[other_side(side)].path
                my_name_there = self.translate(other_side(side), my_name) or ""
                their_name_here = self.translate(side, their_name) or ""

                if my_name_there and their_name_here:
                    if my_name_there > their_name and their_name_here < my_name:  # if the other side's path comes first alphabetically
                        continue
                else:
                    self.state.split(sync)

            try:
                response = self.embrace_change(sync, side, other_side(side))
            except ex.CloudTooManyRetriesError:
                response = FINISHED
                log.exception("too many retries - marked finished %s side:%s", sync, side)

            if response == FINISHED:
                something_got_done = True
                self.finished(side, sync)
            elif response == PUNT:
                sync.punt()
            # otherwise, just do it again, the contract is that returning REQUEUE involved some manual manipulation of the priority
            break

        return something_got_done

    def _temp_file(self, temp_for=None, name=None):
        if not os.path.exists(self.tempdir):
            # in case user deletes it... recreate
            os.mkdir(self.tempdir)
        # prefer big random name over NamedTemp which can infinite loop
        ret = os.path.join(self.tempdir, name or os.urandom(16).hex())

        log.debug("tempdir %s -> %s", self.tempdir, ret)
        if temp_for:
            log.debug("%s is temped by %s", temp_for, ret)
        return ret

    def finished(self, side, sync):
        log.debug("mark finished, clear punts, delete temps")
        sync[side].changed = 0
        # todo: changing the state above should signal this call below
        self.state.finished(sync)

        # todo: likewise... clearing the changebit is enough to know to clear temps
        self.clean_temps(sync)

    @staticmethod
    def clean_temps(sync):
        # todo: move this to the sync obj
        for side in (LOCAL, REMOTE):
            sync[side].clean_temp()

    def make_temp_file(self, ss: SideState):
        """
        Makes a new temporary file, tries to name it in a way that will be consistent between runs.
        """
        if ss.otype == DIRECTORY:
            return
        tfn = None
        if ss.hash:
            # for now hash could be nested tuples of bytes, or just a straight hash
            # probably we should just change it to bytes only
            # but this puts it in a somewhat deterministic form
            tfn = hashlib.md5(bytes(ss.path, "utf8") + msgpack.dumps(ss.hash)).digest().hex()
            if ss.temp_file and tfn in ss.temp_file and os.path.exists(os.path.dirname(ss.temp_file)):
                return

        if ss.temp_file:
            ss.clean_temp()
        ss.temp_file = self._temp_file(name=tfn)

    def download_changed(self, changed, sync):
        """
        Called when it seems a file has changed.  Sticks the result in `sync[changed].temp_file`
        """
        self.make_temp_file(sync[changed])

        assert sync[changed].oid

        if os.path.exists(sync[changed].temp_file):
            log.debug("%s reused %s temp", self.providers[changed], sync[changed].oid)
            return True

        try:
            partial_temp = sync[changed].temp_file + ".tmp"
            log.debug("%s download %s to %s", self.providers[changed].name, sync[changed].oid, partial_temp)
            with open(partial_temp, "wb") as f:
                self.providers[changed].download(sync[changed].oid, f)
            os.rename(partial_temp, sync[changed].temp_file)
            return True
        except FileNotFoundError:
            log.warning("file not found %s", sync[changed].path)
            sync[changed].clean_temp()
            return False
        except PermissionError as e:
            raise ex.CloudTemporaryError("download or rename exception %s" % e)

        except ex.CloudFileNotFoundError:
            log.warning("download from %s failed fnf, switch to not exists",
                      self.providers[changed].name)
            sync[changed].exists = MISSING
            return False

    def get_folder_file_conflict(self, sync: SyncEntry, translated_path: str, synced: int) -> SyncEntry:
        # if a non-dir file exists with the same name on the sync side
        syents: List[SyncEntry] = list(self.state.lookup_path(synced, translated_path))
        conflicts = [ent for ent in syents if ent[synced].exists == EXISTS and ent != sync and ent[synced].otype != DIRECTORY]

        nc: List[SyncEntry] = []
        for ent in conflicts:
            info = self.providers[synced].info_oid(ent[synced].oid)
            if not info:
                if ent[synced].exists != TRASHED:
                    ent[synced].exists = MISSING
            else:
                nc.append(ent)

        return nc[0] if nc else None

    def unsafe_mkdir_synced(self, changed, synced, sync, translated_path):
        log.debug("translated %s as path %s",
                  sync[changed].path, translated_path)

        # could have made a dir that already existed on my side or other side

        chents = list(self.state.lookup_path(changed, sync[changed].path))
        notme_chents = [ent for ent in chents if ent != sync]
        for ent in notme_chents:
            # dup dirs on remote side can be ignored
            if ent[synced].otype == DIRECTORY:
                log.debug("discard duplicate dir entry %s", ent)
                ent.ignore(IgnoreReason.DISCARDED)

        chent: SyncEntry = self.get_folder_file_conflict(sync, translated_path, synced)
        if chent:
            log.info("resolve %s conflict with %s", translated_path, chent)
            # pylint bugs here... no idea why
            self.resolve_conflict((sync[changed], chent[synced]))                   # pylint: disable=unsubscriptable-object
            # the defer entry may not have finished, so PUNT, just in case. If it is finished, it'll clear on the next go
            return PUNT  # fixes test_cs_folder_conflicts_file[mock_oid_cs-prio]

        if self._root_oids[synced]:
            if not self._root_paths[synced]:
                info = self.providers[synced].info_oid(self._root_oids[synced])
                if info:
                    self._root_paths[synced] = info.path
                else:
                    raise ex.CloudRootMissingError("root missing: %s" % self._root_oids[synced])

        if self._root_paths[synced] and self.providers[synced].is_subpath(self._root_paths[synced], translated_path):
            info = self.providers[synced].info_path(self._root_paths[synced])
            if not info:
                raise ex.CloudRootMissingError("root missing: %s" % self._root_paths[synced])
            if info and self._root_oids[synced] and info.oid != self._root_oids[synced]:
                raise ex.CloudRootMissingError("root oid moved: %s" % self._root_paths[synced])

        # make the dir
        oid = self.providers[synced].mkdirs(translated_path)
        log.debug("mkdir %s as path %s oid %s",
                  self.providers[synced].name, translated_path, debug_sig(oid))

        # did i already have that oid? if so, chuck it
        already_dir = self.state.lookup_oid(synced, oid)
        if already_dir and already_dir != sync and already_dir[synced].otype == DIRECTORY:
            log.debug("discard %s", already_dir)
            already_dir.ignore(IgnoreReason.DISCARDED)

        sync[synced].sync_path = translated_path
        sync[changed].sync_path = sync[changed].path

        self.update_entry(
            sync, synced, exists=True, oid=oid, path=translated_path)

        return FINISHED

    def mkdir_synced(self, changed, sync, translated_path):
        """
        Called when it seems a folder has been made.
        """
        synced = other_side(changed)
        # see if there are other entries for the same path, but other ids
        ents = list(self.state.lookup_path(changed, sync[changed].path))
        ents = [ent for ent in ents if ent != sync]
        if ents:
            for ent in ents:
                if ent[changed].otype == DIRECTORY:
                    # these we can toss, they are other folders
                    # keep the current one, since it exists for sure
                    log.debug("discard %s", ent)
                    ent.ignore(IgnoreReason.DISCARDED)

        ents = [ent for ent in ents if TRASHED not in (
            ent[changed].exists, ent[synced].exists)]
        ents = [ent for ent in ents if MISSING not in (
            ent[changed].exists, ent[synced].exists)]

        if ents:
            if sync.priority <= 0:
                log.info("punt mkdir %s", translated_path)  # pragma: no cover
                return PUNT

            log.info("rename to fix conflict %s", translated_path)  # pragma: no cover
            self.rename_to_fix_conflict(sync, synced, translated_path)

        try:
            return self.unsafe_mkdir_synced(changed, synced, sync, translated_path)
        except ex.CloudFileExistsError:
            sync.mark_dirty(synced)

        except ex.CloudFileNotFoundError:
            if sync.priority <= 0:
                return PUNT

            log.warning("mkdir %s : %s failed fnf, TODO fix mkdir code and stuff",
                      self.providers[synced].name, translated_path)
            raise NotImplementedError("TODO mkdir, and make state etc")
        except ex.CloudFileNameError:
            self.handle_file_name_error(sync, synced, translated_path)
            return FINISHED

    def upload_synced(self, changed, sync):
        assert sync[changed].temp_file

        synced = other_side(changed)
        try:
            info = self.providers[synced].upload(
                sync[synced].oid, open(sync[changed].temp_file, "rb"))
            log.debug("upload to %s as path %s",
                      self.providers[synced].name, sync[synced].sync_path)

            sync[synced].hash = info.hash
            sync[synced].sync_hash = info.hash
            if not sync[synced].sync_path:
                sync[synced].sync_path = info.path
            sync[changed].sync_hash = sync[changed].hash
            sync[changed].sync_path = sync[changed].path

            self.update_entry(
                sync, synced, exists=True, oid=info.oid, path=sync[synced].sync_path)
            return True
        except FileNotFoundError:
            log.warning("FNF during upload %s:%s", sync[synced].sync_path, sync[changed].temp_file)
            return False
        except ex.CloudFileNotFoundError:
            info = self.providers[synced].info_oid(sync[synced].oid)

            if not info:
                log.info("convert to missing")
                sync[synced].exists = MISSING
            else:
                # you got an FNF during upload, but when you queried... it existed
                # basically this is just a "retry" or something
                log.warning("Upload to %s failed fnf, info: %s",
                            self.providers[synced].name, info)
            return False
        except ex.CloudFileExistsError:
            # this happens if the remote oid is a folder
            log.info("split bc upload to folder")

            defer_ent, defer_side, replace_ent, replace_side \
                = self.state.split(sync)

            return self.handle_split_conflict(
                defer_ent, defer_side, replace_ent, replace_side)
        except ex.CloudFileNameError:
            # Nothing else to sync
            self.handle_file_name_error(sync, synced, sync[synced].path)
            return True

    def _create_synced(self, changed, sync, translated_path):
        synced = other_side(changed)
        log.debug("create on %s as path %s",
                  self.providers[synced].name, translated_path)
        try:
            with open(sync[changed].temp_file, "rb") as f:
                info = self.providers[synced].create(translated_path, f)
            log.debug("created %s", info)
        except ex.CloudFileExistsError:
            log.warning("exists error %s", translated_path)
            info = self.providers[synced].info_path(translated_path)
            if not info:
                raise
            with open(sync[changed].temp_file, "rb") as f:
                existing_hash = self.providers[synced].hash_data(f)
            if existing_hash != info.hash:
                raise
            log.debug("use existing %s", info)
        except ex.CloudFileNotFoundError:
            raise
        except ex.CloudFileNameError:
            raise
        except Exception as e:
            log.exception("failed to create %s, %s", translated_path, e)
            raise

        assert info.hash
        assert sync[changed].hash
        sync[synced].sync_hash = info.hash
        if info.path:
            sync[synced].sync_path = info.path
        else:
            sync[synced].sync_path = translated_path
        sync[changed].sync_hash = sync[changed].hash
        sync[changed].sync_path = sync[changed].path
        self.update_entry(sync, synced, exists=True, oid=info.oid, path=sync[synced].sync_path, hash=info.hash)

    def update_entry(self, ent, side, oid, *, path=None, hash=None, exists=True, changed=False, otype=None):  # pylint: disable=redefined-builtin
        # updates entry without marking as changed unless explicit
        # used internally
        self.state.update_entry(ent, side, oid, path=path, hash=hash, exists=exists, changed=changed, otype=otype)

    def create_event(self, side, otype, oid, *, path=None, hash=None, exists=True, prior_oid=None):  # pylint: disable=redefined-builtin
        # looks up oid and changes state, marking changed as if it's an event
        # used only for testing
        self.state.update(side, otype, oid, path=path, hash=hash, exists=exists, prior_oid=prior_oid)

    def insert_event(self, side, event: Event):    # pragma: no cover
        # used by event_permute to insert event instead of create/insert above
        self.state.update(side, otype=event.otype, oid=event.oid, path=event.path, hash=event.path,
            exists=event.exists, prior_oid=event.prior_oid)

    def create_synced(self, changed, sync, translated_path):  # pylint: disable=too-many-branches, too-many-statements
        synced = other_side(changed)
        try:
            self._create_synced(changed, sync, translated_path)
            return FINISHED
        except ex.CloudFileNotFoundError:
            return self.handle_cloud_file_not_found_error(changed, sync, synced)
        except ex.CloudFileExistsError:
            # there's a file or folder in the way, let that resolve if possible
            log.info("can't create %s, try punting", translated_path)

            if sync.priority > 0:
                info = self.providers[synced].info_path(translated_path)
                if not info:
                    log.info("got a file exists, and then it didn't exist %s", sync)
                    if sync.priority > 1:
                        log.warning("repeated errors here, converting to pathname error %s", sync)
                        self.handle_file_name_error(sync, synced, translated_path)
                        return FINISHED
                else:
                    sync[synced].oid = info.oid
                    sync[synced].hash = info.hash
                    sync[synced].path = translated_path
                    self.update_entry(sync, synced, info.oid, path=translated_path)
                    # maybe it's a hash conflict
            else:
                # maybe it's a name conflict
                pass
        except ex.CloudFileNameError:
            self.handle_file_name_error(sync, synced, translated_path)
            return FINISHED
        return PUNT

    def handle_cloud_file_not_found_error(self, changed, sync, synced):
        if sync.priority > 5:
            raise ex.CloudTooManyRetriesError("punted too many times on CloudFileNotFoundError, giving up")

        # parent presumably exists
        parent = self.providers[changed].dirname(sync[changed].path)
        log.info("CloudFileNotFoundError, sync %s first before %s", parent, sync[changed].path)
        ents = self.state.lookup_path(changed, parent)
        if not ents:
            info = self.providers[changed].info_path(parent)
            if info:
                self.state.update(changed, DIRECTORY, info.oid, path=parent)
            else:
                log.info("no info and no dir, ignoring")

        else:
            parent_ent = ents[0]
            log.debug("parent=%s", parent_ent)
            if not parent_ent[changed].changed or not parent_ent.is_creation(changed):
                if sync.priority <= 2:  # punt if not already punted, meaning, punt at least once
                    log.info("Provider %s parent folder %s reported missing. punting", self.providers[synced].name, parent)
                    return PUNT
                if parent_ent[changed].exists == EXISTS:
                    # this condition indicates the provider has said the parent folder
                    # doesn't exist, but the statedb says it does exist. First,
                    # double-check using info_oid to see if the the parent DOES in fact exist
                    # even though we got a FNF error before. Providers can take some time to
                    # process a rename or create, so if we rename/create the parent folder,
                    # the exists check on the path may still return false, even though an
                    # exists check on the oid may reveal it does actually exist with the
                    # correct path
                    parent_info = self.providers[synced].info_oid(parent_ent[synced].oid)
                    sync_parent = self.translate(synced, parent)
                    if parent_info and parent_info.path == sync_parent:
                        log.info("Provider %s parent folder %s misreported missing, but parent folder exists. "
                                  "punting", self.providers[synced].name, parent)
                    else:
                        # oddly, everything we know about the file is that it exists, but
                        # the provider insists it doesn't
                        # Clear the sync_path, and set synced to MISSING,
                        # that way, we will recognize that this dir needs to be created
                        parent_ent[changed].sync_path = None
                        parent_ent[changed].changed = time.time()
                        parent_ent[synced].exists = MISSING
                        assert parent_ent.is_creation(changed), "%s is not a creation" % parent_ent
                        assert parent_ent[changed].needs_sync(), "%s doesn't need sync" % parent_ent
                        log.info("updated entry as missing %s", parent_ent)

        log.debug("CloudFileNotFoundError, punt")
        return PUNT

    def handle_file_name_error(self, sync, synced, translated_path):
        # pretend this sync translated as "None"
        log.warning("File name error: not creating '%s' on %s", translated_path, self.providers[synced].name)
        sync.ignore(IgnoreReason.IRRELEVANT)
        if self.__nmgr:
            self.__nmgr.notify(Notification(SourceEnum(synced), NotificationType.FILE_NAME_ERROR, translated_path))

    def __resolve_file_likes(self, side_states):
        class Guard:
            """
            Use this to protect against unclosed file handles.

            Args:
                side_states: Pair of states that will be `ResolveFile`s
            """
            def __init__(guard, side_states):  # pylint: disable=no-self-argument
                guard.side_states = side_states
                guard.fhs: List[ResolveFile] = []

            def __enter__(guard):  # pylint: disable=no-self-argument
                for ss in guard.side_states:
                    assert type(ss) is SideState

                    self.make_temp_file(ss)

                    guard.fhs.append(ResolveFile(ss, self.providers[ss.side]))

                    assert ss.oid
                return guard.fhs

            def __exit__(guard, *args):  # pylint: disable=no-self-argument
                for fh in guard.fhs:
                    fh.close()

        return Guard(side_states)

    def __safe_call_resolver(self, fhs):
        if DIRECTORY in (fhs[0].otype, fhs[1].otype):
            if fhs[0].otype != fhs[1].otype:
                if fhs[0].otype == DIRECTORY:
                    fh = fhs[0]
                else:
                    fh = fhs[1]
                # for simplicity: directory conflicted with file, always favors directory
                return (fh, True)

        is_file_like = lambda f: hasattr(f, "read") and hasattr(f, "close")
        ret = None
        try:
            ret = self._resolve_conflict(*fhs)

            if ret:
                if not isinstance(ret, tuple):
                    log.error("resolve conflict should return a tuple of 2 values, got %s(%s)", ret, type(ret))
                    ret = None
                elif len(ret) != 2:
                    log.error("bad return value for resolve conflict %s", ret)
                    ret = None
                elif not is_file_like(ret[0]):
                    log.error("bad return value for resolve conflict %s", ret)
                    ret = None
        except Exception as e:
            log.exception("exception during conflict resolution %s", e)

        if ret is None:
            # we defer to the remote... since this can prevent loops
            if fhs[0].side == REMOTE:
                ret = (fhs[0], True)
            else:
                ret = (fhs[1], True)

        return ret

    def __resolver_merge_upload(self, side_states, fh, keep):
        # we modified to both sides, need to merge the entries
        ent1, ent2 = side_states

        defer_ent = self.state.lookup_oid(ent1.side, ent1.oid)
        replace_ent = self.state.lookup_oid(ent2.side, ent2.oid)
        new_ent2 = defer_ent[ent2.side]

        if keep:
            # both sides are being kept, so we have to upload since there are no entries
            fh.seek(0)
            info1 = self.providers[ent1.side].create(ent1.path, fh)
            fh.seek(0)
            info2 = self.providers[ent2.side].create(ent2.path, fh)

            ent1.oid = info1.oid
            new_ent2.oid = info2.oid

            self.update_entry(defer_ent, ent1.side, ent1.oid, path=ent1.path, hash=ent1.hash)

            ent1 = defer_ent[ent1.side]
            ent2 = defer_ent[ent2.side]

            assert info2.hash
            assert info1.hash
            new_ent2.sync_hash = info2.hash
            new_ent2.sync_path = info2.path
            ent1.sync_hash = info1.hash
            ent1.sync_path = info1.path
        else:
            info1 = self.providers[ent1.side].info_oid(ent1.oid)
            info2 = self.providers[ent2.side].info_oid(ent2.oid)

            new_ent2.oid = info2.oid
            new_ent2.path = info2.path
            new_ent2.sync_path = new_ent2.path
            ent1.sync_path = self.translate(ent1.side, ent2.path)

        # in case oids have changed
        self.update_entry(defer_ent, ent2.side, ent2.oid, path=ent2.path, hash=ent2.hash)

        defer_ent[ent2.side].sync_hash = ent2.sync_hash
        defer_ent[ent2.side].sync_path = ent2.sync_path
        log.info("keep ent %s", defer_ent)
        log.info("discard ent %s", replace_ent)
        replace_ent.ignore(IgnoreReason.DISCARDED)

    def resolve_conflict(self, side_states):  # pylint: disable=too-many-statements, too-many-branches, too-many-locals
        with self.__resolve_file_likes(side_states) as fhs:
            fh: ResolveFile
            keep: bool
            fh, keep = self.__safe_call_resolver(fhs)

            log.info("keeping ret side %s", getattr(fh, "side", None))
            log.info("fhs[0].side=%s", fhs[0].side)

            defer = None

            # search the fhs for any fh that is going away
            # could be one, the other, or both (if the fh returned by the conflict resolver is a new one, not in fhs)
            for i, rfh in enumerate(fhs):
                if fh is not rfh:  # this rfh is getting replaced (this will be true for at least one rfh)
                    loser = side_states[i]
                    winner = side_states[1 - i]

                    # user didn't opt to keep my rfh
                    log.info("replacing side %s", loser.side)
                    if not keep:
                        log.info("not keeping side %s, simply uploading to replace with new contents", loser.side)
                        fh.seek(0)
                        info2 = self.providers[loser.side].upload(loser.oid, cast(BinaryIO, fh))
                        loser.hash = info2.hash
                        loser.path = info2.path
                        assert info2.hash
                        loser.sync_hash = loser.hash
                        if not loser.sync_path:
                            loser.sync_path = loser.path
                    else:
                        log.info("rename side %s to conflicted", loser.side)
                        try:
                            self._resolve_rename(loser)
                        except ex.CloudFileNotFoundError:
                            log.warning("there is no conflict, because the file doesn't exist? %s", loser)

                    if defer is None:  # the first time we see an rfh to replace, defer gets set to the winner side
                        defer = winner.side
                    else:  # if we replace both rfh, then defer gets set back to None
                        defer = None

            if defer is not None:  # we are replacing one side, not both
                sorted_states = sorted(side_states, key=lambda e: e.side)
                replace_side = other_side(defer)
                replace_ent = self.state.lookup_oid(replace_side, sorted_states[replace_side].oid)
                defer_ent = self.state.lookup_oid(defer, sorted_states[defer].oid)
                if keep:
                    # toss the other side that was replaced
                    if replace_ent:
                        replace_ent.ignore(IgnoreReason.CONFLICT)
                        replace_ent[defer].clear()
                    defer_ent[defer].sync_path = None
                    defer_ent[defer].sync_hash = None
                else:
                    log.info("defer not none, and not keeping, so merge sides")
                    replace_ent[defer] = defer_ent[defer]
                    log.info("discard ent %s", defer_ent)
                    defer_ent.ignore(IgnoreReason.DISCARDED)
                    replace_ent[replace_side].sync_path = replace_ent[replace_side].path
                    replace_ent[replace_side].sync_hash = replace_ent[replace_side].hash
                    replace_ent[defer].sync_path = self.translate(defer, replace_ent[replace_side].path)
                    replace_ent[defer].sync_hash = replace_ent[defer].hash
                    if not replace_ent[defer].sync_path:
                        log.warning("sync path irrelevant during merge")
            else:
                # both sides were modified, because the fh returned was some third thing that should replace both
                log.info("resolver merge upload to both sides: %s", keep)
                self.__resolver_merge_upload(side_states, fh, keep)

            log.info("RESOLVED CONFLICT: %s side: %s", side_states, defer)

    def delete_synced(self, sync, changed, synced, ignore_reason=IgnoreReason.DISCARDED):
        log.debug("try sync deleted %s", sync[changed].path)
        # see if there are other entries for the same path, but other ids
        ents = list(self.state.lookup_path(changed, sync[changed].path))
        ents = [ent for ent in ents if ent != sync]

        for ent in ents:
            if ent.is_creation(synced):
                log.info("discard delete, pending create %s:%s", synced, ent)
                sync.ignore(ignore_reason)
                return FINISHED

        # deletions don't always have paths
        if sync[changed].path:
            translated_path = self.translate(synced, sync[changed].path)
            if translated_path:
                # find conflicting entries that will be  renamed away
                ents = list(self.state.lookup_path(synced, translated_path))
                ents = [ent for ent in ents if ent != sync]
                for ent in ents:
                    if ent.is_rename(synced):
                        log.info("discard delete, pending rename %s:%s", synced, ent)
                        sync.ignore(ignore_reason)
                        return FINISHED

        if sync[synced].oid:
            try:
                log.debug("deleting %s", debug_sig(sync[synced].oid))
                self.providers[synced].delete(sync[synced].oid)
                sync[changed].sync_path = None
            except ex.CloudFileNotFoundError:
                pass
            except ex.CloudFileExistsError:
                return self._handle_dir_delete_not_empty(sync, changed, synced)
        else:
            log.info("was never synced, ignoring deletion")

        sync[synced].exists = TRASHED
        if not sync.is_conflicted:
            log.debug("mark entry discarded %s", sync)
            sync.ignore(ignore_reason, previous_reasons=IgnoreReason.IRRELEVANT)
        return FINISHED

    def _handle_dir_delete_not_empty(self, sync, changed, synced):
        # punt once to allow children to be processed, if already done just forget about it
        if sync.priority > 0:
            all_synced = True
            for kid, _ in self.state.get_kids(sync[changed].path, changed):
                if kid.needs_sync() or not self.translate(synced, sync[changed].path):
                    all_synced = False
                    break
            if all_synced:
                log.info("Attempt dropping dir removal because children appear fully synced %s", sync[changed].path)
                remaining = []
                # Potentially missing ents in state table
                for ent in self.providers[synced].listdir(sync[synced].oid):
                    remaining.append(ent.path or ent.oid)
                    self.state.update(side=synced, otype=ent.otype, oid=ent.oid, path=ent.path, hash=ent.hash,
                            exists=True)
                    self.state.storage_commit()

                if remaining:
                    if sync.priority < 10:
                        log.warning("Children %s exist on side %s. Syncing", remaining, synced)
                        return PUNT
                    else:
                        log.warning("Children %s exist on side %s. Giving up", remaining, synced)
                return FINISHED
            else:
                log.info("all children not fully synced, punt %s", sync[changed].path)
                return PUNT

        # Mark children changed so we will check if already deleted
        log.info("kids exist, mark changed and punt %s", sync[changed].path)
        for kid, _ in self.state.get_kids(sync[changed].path, changed):
            kid[changed].changed = time.time()

        # Mark us changed, so we will sync after kids, not before
        sync[changed].changed = time.time()

        return PUNT

    def _get_untrashed_peers(self, sync, changed, synced, translated_path):
        # check for creation of a new file with another in the table
        if sync[changed].otype != FILE:
            return None

        ents = list(self.state.lookup_path(synced, translated_path))

        # filter for exists
        other_ents = [ent for ent in ents if ent != sync]
        if not other_ents:
            return None

        log.debug("found matching %s, other ents: %s",
                  translated_path, other_ents)

        # ignoring trashed entries with different oids on the same path
        if all(ent[synced].exists != EXISTS for ent in other_ents):
            for ent in other_ents:
                if ent[synced].exists in (TRASHED, MISSING):
                    # old trashed entries can be safely ignored
                    ent.ignore(IgnoreReason.DISCARDED)
            return None

        # filter to the ones that exist remotely
        other_untrashed_ents = [ent for ent in other_ents if ent[synced].exists == EXISTS]

        return other_untrashed_ents

    def check_disjoint_create(self, sync, changed, synced, translated_path):
        other_untrashed_ents = self._get_untrashed_peers(sync, changed, synced, translated_path)

        if not other_untrashed_ents:
            return False

        log.info("split conflict found : %s:%s", len(other_untrashed_ents), other_untrashed_ents)

        found = None
        info = self.providers[synced].info_path(translated_path)
        if not info:
            return False

        if info:
            for e in other_untrashed_ents:
                if e[synced].oid == info.oid:
                    log.debug("same remote oid")
                    if e[synced].sync_hash != e[synced].hash:
                        found = e
                    elif not e[synced].changed:
                        log.info("merge split entries")
                        sync[synced] = e[synced]
                    elif e[synced].otype == DIRECTORY and sync[synced].otype == FILE:
                        # fixes test_cs_folder_conflicts_file
                        found = e
                    elif e[synced].otype == FILE and sync[synced].otype == DIRECTORY:
                        # separate this block out from the previous to assist in code coverage checks
                        found = e
                    else:
                        found = False

        if not found:
            log.info("disjoint conflict with something I don't understand")
            return True

        self.handle_split_conflict(
            found, synced, sync, changed)

        # returns true since we're answering "is-disjoint"
        # todo: change this?
        return True

    def handle_path_change_or_creation(self, sync, changed, synced):  # pylint: disable=too-many-branches, too-many-return-statements
        if not sync[changed].path:
            self.update_sync_path(sync, changed)
            log.debug("NEW SYNC %s", sync)
            if sync[changed].exists == TRASHED or sync.is_discarded:
                log.info("requeue trashed event %s", sync)
                return PUNT

        translated_path = self.translate(synced, sync[changed].path)
        if translated_path is None:
            # ignore these
            return FINISHED

        if not sync[changed].path:
            log.warning("can't sync, no path %s", sync)

        if sync[changed].sync_path and sync[synced].exists == TRASHED:
            # see test: test_sync_folder_conflicts_del
            if sync.priority <= 0:
                log.info("requeue sync + trash priority=%s %s", sync.priority, sync)
                return PUNT

            folder_child_conflict = False
            if sync[changed].otype == DIRECTORY:
                kids = self._get_child_conflict(sync, changed)
                if kids:
                    folder_child_conflict = True
                    log.info("folder child conflict found: %s", kids)

            if sync[synced].changed and not folder_child_conflict:        # rename + delete == delete goes first
                # this is only needed when shuffling
                #   see: test_cs_folder_conflicts_del
                # limiting this branch to only a file fixes test_sharing_conflict_update_file_and_rename_parent_folder
                #   When file is updated locally, deleted remotely, and is in a folder that was renamed locally and deleted remotely
                #   file sync wants to wait on it's parent folder to sync
                #   parent folder punts below because it prioritizes the delete, but can't delete until the
                #   children are synced, so the children waited on the parent and the parent waited on the children
                #   it's ok-ish if a folder that was renamed and deleted converts to a create of the new name

                if sync[changed].sync_hash == sync[changed].hash:
                    sync[changed].changed = sync[synced].changed + .01
                    log.info("reprioritize sync + trash %s  (%s, %s)", sync, sync[changed].changed, sync[synced].changed)
                    return PUNT

            # folder event getting here implies that there is a child conflict, so create is appropriate
            sync[synced].clear()
            log.debug("cleared trashed info, converting to create %s", sync)

        if sync.is_creation(changed) and sync.priority == 0 and sync[synced].exists == MISSING:
            log.info("create on top of missing, punt, maybe a rename")
            return PUNT

        if sync.is_creation(changed):
            # never synced this before, maybe there's another local path with
            # the same name already?
            if self.check_disjoint_create(sync, changed, synced, translated_path):
                log.info("disjoint, requeue")
                return PUNT

        if sync.is_creation(changed):
            # looks like a new file

            if sync[changed].otype == DIRECTORY:
                return self.mkdir_synced(changed, sync, translated_path)

            if not self.download_changed(changed, sync):
                return PUNT

            if sync[synced].oid and sync[synced].exists not in (TRASHED, MISSING):
                if self.upload_synced(changed, sync):
                    return FINISHED
                return PUNT

            return self.create_synced(changed, sync, translated_path)

        return self.handle_rename(sync, changed, synced, translated_path)

    def handle_rename(self, sync, changed, synced, translated_path):            # pylint: disable=too-many-branches,too-many-statements,too-many-return-statements
        # handle rename
        # use == to allow rename for case reasons
        # todo: need a paths_match flag instead, so slashes don't break this line
        if sync[synced].sync_path == translated_path:
            return FINISHED

        assert sync[synced].sync_hash or sync[synced].otype == DIRECTORY

        if self.providers[synced].paths_match(translated_path, sync[synced].sync_path, for_display=True):
            log.debug("no rename %s %s", translated_path, sync[synced].sync_path)
            return FINISHED

        log.debug("rename %s %s", sync[synced].sync_path, translated_path)
        try:
            new_oid = self.providers[synced].rename(sync[synced].oid, translated_path)
        except ex.CloudFileNotFoundError as e:
            log.warning("ERROR: can't rename for now %s: %s", sync, repr(e))
            return self.handle_cloud_file_not_found_error(changed, sync, synced)
        except ex.CloudFileNameError as e:
            self.handle_file_name_error(sync, synced, translated_path)
            return FINISHED
        except ex.CloudFileExistsError:
            log.warning("can't rename, file exists")
            if sync.priority <= 0:
                sync.get_latest(force=True)
            else:
                ents = self.state.lookup_path(synced, translated_path)
                ents = [e for e in ents if e is not sync]

                if ents:
                    conflict = ents[0]
                    conflict.get_latest()
                    if not conflict[LOCAL].needs_sync() and not conflict[REMOTE].needs_sync():
                        # file is up to date, we're replacing a known synced copy
                        try:
                            self.providers[synced].delete(conflict[synced].oid)
                            log.info("deleting %s out of the way", translated_path)
                            conflict[synced].exists = TRASHED
                            if not conflict[changed].oid:
                                # conflict row was because of a rename on-to-of
                                # oid got zeroed out....
                                # todo: handle this more gracefully
                                conflict.ignored = IgnoreReason.DISCARDED
                            return PUNT
                        except ex.CloudFileExistsError:
                            pass
                    log.debug("rename to fix conflict %s because %s not synced, NS: %s", translated_path, conflict, conflict.needs_sync())
                else:
                    log.debug("rename because of new/unknown content")

                try:
                    self.rename_to_fix_conflict(sync, synced, translated_path, temp_rename=True)
                except ex.CloudFileNotFoundError as e:
                    log.error("file disappeared out from under us %s", e)
                    log.info("%s", self.state.pretty_print())
                    sync.get_latest(force=True)

                self.rename_to_fix_conflict(sync, synced, translated_path, temp_rename=True)

            return PUNT

        sync[synced].sync_path = translated_path
        sync[changed].sync_path = sync[changed].path
        self.update_entry(sync, synced, path=translated_path, oid=new_oid)
        return FINISHED

    def _resolve_rename(self, replace):
        _old_oid, new_oid, new_path = self.conflict_rename(replace.side, replace.path)
        if new_path is None:
            return False

        # TODO:
        #   we rename the file to resolve the conflict, but we don't update the path in the replace SideState
        #   this is OK-ish, because we update replace.changed, and get_latest will update the name to the new one
        #   the reason why we leave the old path is that we're going to use it in a second if we're doing a merge,
        #   and we don't save it anywhere else. This is probably a terrible place to temporarily store
        #   that name, so we should actually do the `replace.path = new_path` and find a way to return the old path
        #   back to the merge code, and have it use that. This is the code we will need:
        # replace.path = new_path # this will break test_sync_conflict_resolve, until the above is addressed

        replace.oid = new_oid
        replace.changed = time.time()
        return True

    def rename_to_fix_conflict(self, sync, side, path, temp_rename=False):
        old_oid, new_oid, new_name = self.conflict_rename(side, path)
        if new_name is None:
            return False

        # file can get renamed back, if there's a cycle
        if old_oid == sync[side].oid:
            self.update_entry(sync, side=side, oid=new_oid)
            if temp_rename:
                sync.ignore(IgnoreReason.TEMP_RENAME)
        else:
            ent = self.state.lookup_oid(side, old_oid)
            if ent:
                self.update_entry(ent, side=side, oid=new_oid)
                if temp_rename:
                    ent.ignore(IgnoreReason.TEMP_RENAME)

        return True

    def conflict_rename(self, side, path):
        folder, base = self.providers[side].split(path)
        if base == "":
            raise ValueError("bad path %s" % path)

        index = base.find(".")
        if index >= 0:
            ext = base[index:]
            base = base[:index]
        else:
            # base = base
            ext = ""

        oinfo = self.providers[side].info_path(path)

        if not oinfo:
            return None, None, None

        i = 1
        new_oid = None
        conflict_name = base + ".conflicted" + ext
        while new_oid is None:
            try:
                conflict_path = self.providers[side].join(folder, conflict_name)
                new_oid = self.providers[side].rename(oinfo.oid, conflict_path)
            except ex.CloudFileExistsError:
                log.info("already exists %s", conflict_name)
                i = i + 1
                conflict_name = base + ".conflicted" + str(i) + ext

        log.info("conflict renamed: %s -> %s", path, conflict_path)
        return oinfo.oid, new_oid, conflict_path

    def embrace_change(self, sync, changed, synced):  # pylint: disable=too-many-return-statements, too-many-branches
        log.debug("embrace %s, side:%s", sync, changed)

        if sync[changed].path or (sync[changed].exists == EXISTS):
            translated_path = self.translate(synced, sync[changed].path)
            if not translated_path:
                if sync[changed].sync_path:  # This entry was relevent, but now it is irrelevant
                    log.info(">>>Removing remnants of file moved out of cloud root")
                    ret = self.delete_synced(sync, changed, synced, IgnoreReason.IRRELEVANT)
                    if ret == FINISHED:
                        self.state.split(sync)
                    return ret
                else:  # we don't have a new or old translated path... just irrelevant so discard
                    log.log(TRACE, ">>>Not a cloud path %s, ignoring", sync[changed].path)
                    sync.ignore(IgnoreReason.IRRELEVANT)

        if sync.is_discarded:
            log.log(TRACE, "%s Ignoring entry because %s:%s", debug_sig(id(self)), sync.ignored.value, sync)
            return FINISHED

        if sync.is_conflicted:
            log.info("Conflicted file %s is changing", sync[changed].path)
            if "conflicted" in sync[changed].path:
                return FINISHED
            else:
                sync.unignore(IgnoreReason.CONFLICT)

        if sync[changed].path and sync[changed].exists == EXISTS and not sync.is_pending_delete():
            # parent_conflict code
            conflict = self._get_parent_conflict(sync, changed)
            if conflict:
                conflict[changed].set_aged()
                # gentle punt, based on whichever is higher priority
                # we want the sync priority to have the priority of the higher priority item
                # then we want the conflict priority to be *slightly* higher than that
                # that way, if we find a grandparent that needs to happen before the parent,
                # mom will either stay where she is or get pushed up even higher priority
                # and grandma will get pushed up before mom. It is also important to prevent priorities
                # that are >=0 to stay >=0, because priorities that are <0 have special handling
                min_priority = min(sync.priority, conflict.priority)
                if min_priority < 0:
                    sync.priority = min_priority
                    conflict.priority = min_priority - 0.1
                else:
                    sync.priority = min_priority + 0.1
                    conflict.priority = min_priority

                log.info("parent modify %s should happen first %s", sync[changed].path, conflict)
                if sync.is_path_change(changed) and sync[synced].exists == TRASHED and sync.priority > 2:
                    # right hand side was trashed at the same time as a rename happened
                    # punting is in a loop
                    # force the trash to sync instead
                    # removing this flakes test: folder_conflicts_del shuffled/oid_is_path version
                    # also breaks test_folder_del_loop
                    sync[synced].changed = 1

                return REQUEUE  # we don't want to punt here, we just manually adjusted the priority above

        if sync[changed].exists == TRASHED:
            log.debug("delete")
            return self.delete_synced(sync, changed, synced)

        if sync[changed].exists == MISSING:
            return self.handle_changed_is_missing(sync, changed, synced)

        if sync.is_path_change(changed) or sync.is_creation(changed):
            log.debug("is_path_change %s", sync.is_path_change(changed))
            ret = self.handle_path_change_or_creation(sync, changed, synced)
            if ret == PUNT:
                log.debug("requeue, not handled")
                return PUNT

            if sync.is_discarded:
                return FINISHED

            # fall through in case of hash change

        if sync[changed].hash != sync[changed].sync_hash:
            return self.handle_hash_diff(sync, changed, synced)

        log.debug("nothing changed %s", sync)
        return FINISHED

    def handle_changed_is_missing(self, sync, changed, synced):     # pylint: disable=no-self-use
        log.info("%s missing", sync[changed].path)

        if sync[synced].exists == EXISTS:
            if sync.priority <= 4:
                log.warning("%s missing, other side exists. punting: %s", sync[changed].path, sync)
                return PUNT
            # The synced side thinks it's synced, but it isn't -- the file is missing on the changed side
            # We need to not only mark the synced side as changed, but UNSYNC it by removing the sync path
            # otherwise needs_sync will return False,
            log.warning("%s missing, other side exists. Marking other side unsynced: %s", sync[changed].path, sync)
            sync[changed].clear()
            sync[synced].sync_path = None
            sync[synced].sync_hash = None
            sync[synced].changed = time.time()
            log.warning("%s now unsynced: %s", sync[synced].path, sync)

        return FINISHED

    def handle_hash_diff(self, sync, changed, synced):
        if sync[changed].path is None:
            return FINISHED

        if sync[synced].exists in (TRASHED, MISSING) or sync[synced].oid is None:
            log.debug("dont upload new contents over an already deleted file, instead zero out trashed side "
                      "turning the 'upload' into a 'create'")
            # not an upload
            # todo: change to clear()
            sync[synced].exists = UNKNOWN
            sync[synced].hash = None
            sync[synced].changed = 0
            sync[synced].path = None
            sync[synced].oid = None
            sync[synced].sync_path = None
            sync[synced].sync_hash = None
            sync[changed].sync_path = None
            sync[changed].sync_hash = None
            return PUNT

        log.debug("needs upload: %s index: %s bc %s != %s", sync, synced, sync[changed].hash, sync[changed].sync_hash)

        assert sync[synced].oid

        if not self.download_changed(changed, sync):
            return PUNT
        if not self.upload_synced(changed, sync):
            return PUNT
        return FINISHED

    def update_sync_path(self, sync, changed):
        assert sync[changed].oid

        info = self.providers[changed].info_oid(sync[changed].oid)
        if not info:
            log.info("marking missing %s", debug_sig(sync[changed].oid))
            sync[changed].exists = MISSING
            return

        if not info.path:
            log.warning("impossible sync, no path. "
                        "Probably a file that was shared, but not placed into a folder. discarding. %s",
                        sync[changed])
            sync.ignore(IgnoreReason.DISCARDED)
            return

        log.debug("UPDATE PATH %s->%s", sync, info.path)
        self.update_entry(
            sync, changed, sync[changed].oid, path=info.path, exists=True)

    def handle_hash_conflict(self, sync):
        log.debug("splitting hash conflict %s %s %s", sync, sync[LOCAL].sync_hash, sync[REMOTE].sync_hash)

        try:
            save: Tuple[Dict[str, Any], Dict[str, Any]] = ({}, {})
            for side in (LOCAL, REMOTE):
                for field in ("sync_hash", "sync_path", "oid", "hash", "path", "exists"):
                    save[side][field] = getattr(sync[side], field)
            # split the sync in two
            defer_ent, defer_side, replace_ent, replace_side \
                = self.state.split(sync)
            return self.handle_split_conflict(
                defer_ent, defer_side, replace_ent, replace_side)
        except ex.CloudException as e:
            log.info("exception during hash conflict split: %s", e)
            for side in (LOCAL, REMOTE):
                for field in ("sync_hash", "sync_path", "oid", "hash", "path", "exists"):
                    setattr(defer_ent[side], field, save[side][field])
            replace_ent.ignore(IgnoreReason.DISCARDED)
            raise

    def handle_split_conflict(self, defer_ent, defer_side, replace_ent, replace_side):
        if defer_ent[defer_side].otype == FILE:
            if not self.download_changed(defer_side, defer_ent):
                return False
            try:
                with open(defer_ent[defer_side].temp_file, "rb") as f:
                    dhash = self.providers[replace_side].hash_data(f)
                    if dhash == replace_ent[replace_side].hash:
                        log.debug("same hash as remote, discard one side and merge")
                        defer_ent[replace_side] = replace_ent[replace_side]
                        defer_ent[replace_side].sync_hash = defer_ent[replace_side].hash
                        defer_ent[defer_side].sync_hash = defer_ent[defer_side].hash
                        defer_ent[replace_side].sync_path = defer_ent[replace_side].path
                        defer_ent[defer_side].sync_path = defer_ent[defer_side].path
                        replace_ent.ignore(IgnoreReason.DISCARDED)
                        return True
            except FileNotFoundError:
                return False

        log.debug(">>> about to resolve_conflict")
        self.resolve_conflict((defer_ent[defer_side], replace_ent[replace_side]))
        return True

    def _get_child_conflict(self, sync: SyncEntry, changed):
        return [kid[0] for kid in self.state.get_kids(sync[changed].path, changed) if not kid[0].is_pending_delete()]

    def _get_parent_conflict(self, sync: SyncEntry, changed) -> SyncEntry:
        provider = self.providers[changed]
        path = sync[changed].path
        parent = provider.dirname(path)
        ret = None
        while path != parent:
            ents = list(self.state.lookup_path(changed, parent))
            for ent in ents:
                if ent[changed].changed and ent[changed].exists == EXISTS:
                    ret = ent
            path = parent
            parent = provider.dirname(path)
        return ret
