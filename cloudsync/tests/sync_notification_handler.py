from typing import Optional, Tuple, List, Union
import logging

from cloudsync import CloudSync
from cloudsync.notification import Notification, NotificationType, SourceEnum
from cloudsync.types import LOCAL, REMOTE, OInfo
from cloudsync.tests.fixtures import RunUntilHelper

log = logging.getLogger(__name__)


class SyncNotificationHandler:
    """ Class that allows tests or other consumers to know when SyncManager chooses to not sync a file """
    def __init__(self, csync: CloudSync):
        self.skipped_paths: set = set()
        self.discarded_paths: set = set()
        self.corrupt_paths: set = set()
        self.csync = csync

    def handle_notification(self, notification: Notification):
        """ implementation of callback that logs when files are discarded or skipped by SmartSync """
        n = notification

        if n.ntype == NotificationType.SYNC_SMART_UNSYNCED and n.source == SourceEnum.LOCAL:  # pragma: no cover
            return  # only interested in REMOTE events, because smartsync operates primarily remotely

        if n.ntype == NotificationType.SYNC_SMART_UNSYNCED:
            self.skipped_paths.add(n.path)
        elif n.ntype == NotificationType.SYNC_DISCARDED:
            self.discarded_paths.add(n.path)
        elif n.ntype == NotificationType.SYNC_CORRUPT_IGNORED:
            self.corrupt_paths.add(n.path)

    @staticmethod
    def _path_in(path, paths, provider):
        """ Checks if path is in path_dict, the keys of which are remote paths """
        for candidate in paths:
            if provider.paths_match(path, candidate):
                return True
        return False

    def _is_synced(self, side, path, hash_str):
        info: OInfo = self.csync.providers[side].info_path(path)
        return info and (not hash_str or info.hash == hash_str)

    def clear_sync_state(self):
        """ Resets the log of synced/skipped paths """
        self.skipped_paths = set()
        self.discarded_paths = set()
        self.corrupt_paths = set()

    def check_sync_state(  # pylint: disable=too-many-branches
            self,
            *,
            remote_paths: Optional[Union[List[str], List[Tuple[str, str]]]] = None,  # tuple is (path, hash)
            local_paths: Optional[Union[List[str], List[Tuple[str, str]]]] = None,
            skipped_paths: Optional[Union[List[str], List[Tuple[str, str]]]] = None,
            discarded_paths: Optional[Union[List[str], List[Tuple[str, int]]]] = None,  # tuple is (path, side)
            quiet=False
    ):
        """ Returns True if synced_paths have synced and skipped_paths have explicitly been skipped """
        if not (remote_paths or local_paths or skipped_paths or discarded_paths):
            raise ValueError("Specify remote_paths or local_paths or skipped_paths or discarded_paths")

        retval = True
        for path in remote_paths or []:
            hash_str = None
            if isinstance(path, tuple):
                path, hash_str = path
            if not self._is_synced(REMOTE, path, hash_str):
                if not quiet:
                    log.error("%s not synced remotely", path)
                retval = False

        for path in local_paths or []:
            hash_str = None
            if isinstance(path, tuple):
                path, hash_str = path
            if not self._is_synced(LOCAL, path, hash_str):
                if not quiet:
                    log.error("%s not synced locally", path)
                retval = False

        for path in skipped_paths or []:
            if isinstance(path, tuple):
                path, _ = path
            if not self._path_in(path, self.skipped_paths, self.csync.providers[REMOTE]):
                if not quiet:
                    log.error("%s not found in skipped paths %s", path, self.skipped_paths)
                retval = False

        for path2 in discarded_paths or []:
            side = REMOTE
            if isinstance(path2, tuple):
                path2, side = path2
            if not self._path_in(path2, self.discarded_paths, self.csync.providers[side]):
                if not quiet:
                    log.error("%s not found in discarded paths %s", path2, self.discarded_paths)
                retval = False

        return retval

    def wait_sync_state(self,
                        *,
                        remote_paths: Optional[Union[List[str], List[Tuple[str, str]]]] = None,
                        local_paths: Optional[Union[List[str], List[Tuple[str, str]]]] = None,
                        skipped_paths: Optional[Union[List[str], List[Tuple[str, str]]]] = None,
                        discarded_paths: Optional[Union[List[str], List[Tuple[str, int]]]] = None,
                        timeout=20,
                        poll_time=0.25,
                        exc=None):
        """ Waits for when synced paths have been synced and skipped paths have been explicitly skipped """
        if not (remote_paths or local_paths or skipped_paths or discarded_paths):
            raise ValueError("Specify remote_paths or local_paths or skipped_paths or discarded_paths")
        try:
            RunUntilHelper.wait_until(
                until=lambda: self.check_sync_state(
                    remote_paths=remote_paths,
                    local_paths=local_paths,
                    skipped_paths=skipped_paths,
                    discarded_paths=discarded_paths,
                    quiet=True),
                timeout=timeout,
                poll_time=poll_time,
                exc=exc
            )
        except Exception:
            # one last check, and also log what is missing
            if not self.check_sync_state(
                    remote_paths=remote_paths, local_paths=local_paths, skipped_paths=skipped_paths, quiet=False
            ):
                raise
