import logging
import time
from typing import TYPE_CHECKING, Optional, Callable, Any
from dataclasses import dataclass, replace
from pystrict import strict

from .exceptions import CloudTemporaryError, CloudDisconnectedError, CloudCursorError, CloudTokenError, CloudFileNotFoundError, \
    CloudNamespaceError, CloudRootMissingError
from .runnable import Runnable
from .types import OType, DIRECTORY
from .notification import SourceEnum

if TYPE_CHECKING:
    from cloudsync.sync import SyncState
    from cloudsync import Provider
    from cloudsync.notification import NotificationManager
    from typing import Tuple, List

log = logging.getLogger(__name__)


@dataclass
class Event:
    otype: OType                                # fsobject type     (DIRECTORY or FILE)
    oid: str                                    # fsobject id
    path: Optional[str]                         # path
    hash: Any                                   # fsobject hash     (better name: ohash)
    exists: Optional[bool]
    mtime: Optional[float] = None
    prior_oid: Optional[str] = None             # path based systems use this on renames
    new_cursor: Optional[str] = None


class ProviderGuard(set):
    def add(self, provider):
        if provider in self:
            raise ValueError("Provider instances should not be re-used in multiple syncs.  Create a new provider instance.")
        super().add(provider)

    def remove(self, provider):
        if provider in self:
            super().remove(provider)


@strict             # pylint: disable=too-many-instance-attributes
class EventManager(Runnable):
    """Runnable that is owned by CloudSync, reading events and updating the SyncState."""

    _provider_guard = ProviderGuard()

    def __init__(self, provider: "Provider", state: "SyncState", side: int,              # pylint: disable=too-many-arguments
                 notification_manager: 'Optional[NotificationManager]' = None,
                 root_path: Optional[str] = None, reauth: Callable[[], None] = None,
                 root_oid: Optional[str] = None):
        log.debug("provider %s, root %s", provider.name, root_path)

        if not provider.connection_id:
            raise ValueError("provider must be connected when starting the event manager")

        self._provider_guard.add(provider)
        self.provider = provider

        self.label: str = f"{self.provider.name}:{self.provider.connection_id}:{self.provider.namespace_id}"
        self.state: 'SyncState' = state
        self.side: int = side
        self.__nmgr = notification_manager
        self._queue: 'List[Tuple[Event, bool]]' = []
        self.need_auth = False

        self.cursor: Any = None
        self._cursor_tag: Optional[str] = None
        self._walk_tag: Optional[str] = None
        self.need_walk: bool = False
        self._root_path: Optional[str] = root_path
        self._root_oid: Optional[str] = root_oid
        self._root_validated: bool = False
        self._validate_root()

        self._first_do = True
        self.min_backoff = provider.default_sleep / 10
        self.max_backoff = provider.default_sleep * 10
        self.mult_backoff = 2
        self.reauthenticate = reauth or self.__reauth

    def _validate_root(self):
        if not self._root_validated and self.provider.connected:
            (self._root_path, self._root_oid) = self.provider.set_root(self._root_path, self._root_oid)
            my_root = self._root_path or self._root_oid
            if my_root:
                self._walk_tag = self.label + "_walked_" + my_root
                self._cursor_tag = self.label + "_cursor_" + my_root
                self.cursor = self.state.storage_get_data(self._cursor_tag)
                self.need_walk = self.cursor is None or self.state.storage_get_data(self._walk_tag) is None
            else:
                self._cursor_tag = self.label = "_cursor"
                self.cursor = self.state.storage_get_data(self._cursor_tag)
            self._root_validated = True
        return self._root_validated

    def __reauth(self):
        self.provider.connect(self.provider.authenticate())

    def forget(self):
        self._first_do = True
        self.need_walk = True

        if self._walk_tag is not None:
            self.state.storage_delete_tag(self._walk_tag)
        if self._cursor_tag is not None:
            self.state.storage_delete_tag(self._cursor_tag)

    @property
    def busy(self):
        if self._queue or self.need_walk:
            return True
        for event in self.provider.events():
            self.queue(event)
            return True
        return False

    def _reconnect_if_needed(self):
        if not self.provider.connected:
            if self.need_auth:
                try:
                    # possibly this is a temporary loss of authorization
                    self.provider.reconnect()
                except CloudTokenError:
                    log.warning("Need auth, calling reauthenticate")
                    try:
                        self.reauthenticate()
                    except NotImplementedError:
                        raise CloudTokenError("No auth method defined")
                self.need_auth = False
            else:
                log.info("reconnect to %s", self.provider.name)
                self.provider.reconnect()

    def do(self):
        try:
            self._reconnect_if_needed()
            if self._validate_root():
                self._do_unsafe()
        except (CloudTemporaryError, CloudDisconnectedError, CloudNamespaceError) as e:
            # CloudRootMissingError is a CloudTemporaryError so handled here
            log.warning("temporary error %s[%s] in event watcher", type(e), e)
            if self.__nmgr:
                self.__nmgr.notify_from_exception(SourceEnum(self.side), e)
            self.backoff()
        except CloudCursorError as e:
            log.exception("Cursor error... resetting cursor. %s", e)
            self.provider.current_cursor = self.provider.latest_cursor
            self._save_current_cursor()
            self.backoff()
        except CloudTokenError:
            # this is separated from the main block because
            # it can be raised during reconnect in the exception handler and in do_unsafe
            self.need_auth = True
            self.backoff()

    def _do_walk_if_needed(self):
        if self.need_walk:
            log.debug("walking all %s/%s-%s files as events, because no working cursor on startup",
                      self.provider.name, self._root_path, self._root_oid)
            self._queue = []
            self._do_walk_oid(self._root_oid)
            self.state.storage_update_data(self._walk_tag, time.time())
            self.need_walk = False

    def _do_walk_oid(self, oid):
        try:
            if oid:
                for event in self.provider.walk_oid(oid):
                    self._process_event(event, from_walk=True)
        except CloudFileNotFoundError as e:
            log.debug('File to walk not found %s', e)

    def _do_first_init(self):
        if self._first_do:
            if self.cursor is None:
                self.cursor = self.provider.current_cursor
                if self.cursor is not None:
                    self.state.storage_update_data(self._cursor_tag, self.cursor)
            else:
                log.debug("retrieved existing cursor %s for %s", self.cursor, self.provider.name)
                try:
                    # valid exceptions here are Disconnected, Token, and Cursor
                    self.provider.current_cursor = self.cursor
                except CloudCursorError:
                    if self.state.storage_get_data(self._walk_tag) is None:
                        self.need_walk = True
                    raise
            self._first_do = False

    def _do_unsafe(self):
        self._do_first_init()
        self._do_walk_if_needed()

        # user supplied events
        if self._queue:
            log.debug("User supplied events")
            for (event, from_walk) in self._queue:
                self._process_event(event, from_walk=from_walk)
            self._queue = []

        # regular events
        for event in self.provider.events():
            if not event:
                log.error("%s got BAD event %s", self.label, event)
                continue
            self._process_event(event)

        self._save_current_cursor()

    def _save_current_cursor(self):
        current_cursor = self.provider.current_cursor

        if current_cursor != self.cursor:
            self.state.storage_update_data(self._cursor_tag, current_cursor)
            self.cursor = current_cursor

    def _drain(self):
        # for tests, delete events
        self._queue = []
        for _ in self.provider.events():
            pass

    def queue(self, event: Event, from_walk: bool = False):
        """Queue an event for processing.   Called for walks."""
        self._queue.append((event, from_walk))

    def _process_event(self, event: Event, from_walk=False):
        """
        Called once for each event.

        Args:
            event: the event received
            from_walk: whether the event was a fake one received during a walk

        This function updates the state database with information from the event.

        Attempts are made to resolve the path.

        The backing store is written to afterward.
        """
        with self.state.lock:
            log.debug("%s got event %s, fw: %s", self.label, event, from_walk)

            event = replace(event)

            if event.oid is None:
                if not event.exists and event.path and event.otype == DIRECTORY:
                    # allow no oid on deletion of folders
                    # this is because of dropbox
                    known = self.state.lookup_path(self.side, event.path)
                    if known:
                        log.debug("using known oid for %s", event.path)
                        event.oid = known[0][self.side].oid

            if event.oid is None:
                log.warning("ignoring event %s, no oid", event)
                return

            if from_walk:
                if not event.path:
                    log.error("walk %s without full path", self.provider.name)  # pragma: no cover

                already = self.state.lookup_oid(self.side, event.oid)
                if already:
                    changed = already[self.side].hash != event.hash or already[self.side].path != event.path
                    if not changed:
                        # ignore from_walk events where nothing changed
                        return

            if self._filter_event(event, from_walk):
                log.debug("filtered out: %s %s %s", event.path, event.oid, event.exists)
                return

            self._fill_event_path(event)
            self._notify_on_root_change_event(event)
            self.state.update(self.side, event.otype, event.oid, path=event.path, hash=event.hash,
                              exists=event.exists, prior_oid=event.prior_oid)
            self.state.storage_commit()

    def _fill_event_path(self, event: Event):
        if event.path:
            return
        if event.prior_oid:
            log.error("rename from oid_is_path %s without full path", self.provider.name)   # pragma: no cover
        state = self.state.lookup_oid(self.side, event.oid)
        if state:
            event.path = state[self.side].path
        if not event.path and event.exists:
            # TODO: is this really necessary?
            # could we let SyncManager handle this (it calls get_latest on every change) instead?
            info = self.provider.info_oid(event.oid)
            if info:
                event.path = info.path
                event.otype = info.otype
                event.hash = info.hash

    def _filter_event(self, event: Event, from_walk: bool = False) -> bool:
        # event filtering based on root path and event path
        # return True = ignore event (filter it out), False = process event

        # for now only OneDrive supports event filtering
        support_filtering = self.provider.name == "onedrive"
        support_filtering_test = self.provider.name[:4] == "Mock" and not self.provider.oid_is_path
        if not (support_filtering or support_filtering_test):
            return False

        if not self._root_path:
            return False

        state = self.state.lookup_oid(self.side, event.oid)
        state_path = state[self.side].path if state else None
        prior_subpath = self.provider.is_subpath_of_root(state_path)
        if not event.exists:
            # delete - ignore if not in state, or in state but is not subpath of root
            return not prior_subpath

        if not event.path:
            return False

        ignore = False
        curr_subpath = self.provider.is_subpath_of_root(event.path)
        if curr_subpath and not prior_subpath:
            # rename into root
            if event.otype == DIRECTORY and not from_walk:
                log.debug("directory renamed into root - walking: %s", event.path)
                self._process_event(event, from_walk=True)
                self._do_walk_oid(event.oid)
                ignore = True
            log.debug("renamed into root: %s", event.path)
        elif prior_subpath and not curr_subpath:
            # rename out of root
            log.debug("renamed out of root: %s", event.path)
        else:
            # both curr and prior are subpaths == rename within root (process event)
            # neither is subpath == rename outside root (ignore)
            ignore = not curr_subpath
        return ignore

    def _notify_on_root_change_event(self, event: Event):
        if self._root_path and self._root_oid:
            if self.provider.root_oid == event.oid:
                if not event.exists:
                    raise CloudRootMissingError(f"root was deleted for provider: {self.provider.name}")
                if event.path and not self.provider.paths_match(self.provider.root_path, event.path):
                    raise CloudRootMissingError(f"root was renamed for provider: {self.provider.name}")
            if self.provider.root_oid == event.prior_oid:
                raise CloudRootMissingError(f"root was renamed for provider: {self.provider.name}")

    def done(self):
        self._provider_guard.remove(self.provider)
        super().done()

    def stop(self, forever=True, wait=True):
        self.provider.disconnect()
        super().stop(forever=forever, wait=wait)
