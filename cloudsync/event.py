import logging
import time
from typing import TYPE_CHECKING, Optional, Callable, Any
from dataclasses import dataclass, replace
from pystrict import strict

from .exceptions import CloudTemporaryError, CloudDisconnectedError, CloudCursorError, CloudTokenError, CloudFileNotFoundError, CloudNamespaceError
from .runnable import Runnable
from .types import OType, DIRECTORY
from .notification import SourceEnum
#from .provider import Cursor

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


_provider_guard = ProviderGuard()


@strict             # pylint: disable=too-many-instance-attributes
class EventManager(Runnable):
    """Runnable that is owned by CloudSync, reading events and updating the SyncState."""
    def __init__(self, provider: "Provider", state: "SyncState", side: int,              # pylint: disable=too-many-arguments
                 notification_manager: 'Optional[NotificationManager]' = None,
                 root_path: Optional[str] = None, reauth: Callable[[], None] = None,
                 root_oid: Optional[str] = None):
        log.debug("provider %s, root %s", provider.name, root_path)
        if not provider.connection_id:
            raise ValueError("provider must be connected when starting the event manager")

        _provider_guard.add(provider)
        self.provider = provider
        self.label: str = f"{self.provider.name}:{self.provider.connection_id}:{self.provider.namespace_id}"
        
        self.state: 'SyncState' = state
        self.side: int = side
        self.__nmgr = notification_manager
        self._queue: 'List[Tuple[Event, bool]]' = []
        self.need_auth = False
        self.reauthenticate = reauth or self.__reauth
        self._first_do = True
        self.min_backoff = provider.default_sleep / 10
        self.max_backoff = provider.default_sleep * 10
        self.mult_backoff = 2

        self.root_oid: str = root_oid
        self.root_path: str = root_path
        self.cursor = None
        self._cursor_tag: str = None
        self._walk_tag: str = None
        self.need_walk: bool = False
        self._need_init_root = True

        try:
            # this is an online operation if root_path or root_oid is specified
            self._init_root()
        except CloudDisconnectedError:
            log.info("root init failed (disconnected) - will retry on reconnect")


    def _init_root(self):
        if self._need_init_root:
            (self.root_path, self.root_oid) = self.provider.set_root(self.root_path, self.root_oid)
            if self.root_path or self.root_oid:
                self._cursor_tag = self.label + "_cursor_" + (self.root_path or self.root_oid)
                self._walk_tag = self.label + "_walked_" + (self.root_path or self.root_oid)
                self.need_walk = self.cursor is None or self.state.storage_get_data(self._walk_tag) is None
            else:
                self._cursor_tag = self.label = "_cursor"
            self.cursor = self.state.storage_get_data(self._cursor_tag)
            self._need_init_root = False


    def _reconnect(self):
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
            self._init_root()

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
        self.do()
        return self.need_walk

    def do(self):
        try:
            self._reconnect()
            self._do_unsafe()
        except (CloudTemporaryError, CloudDisconnectedError, CloudNamespaceError) as e:
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
            log.debug("walking all %s/%s-%s files as events",
                      self.provider.name, self.root_path, self.root_oid)
            self._queue = []
            try:
                if self.root_path:
                    for event in self.provider.walk(self.root_path):
                        self._process_event(event, from_walk=True)
                else:
                    for event in self.provider.walk_oid(self.root_oid):
                        self._process_event(event, from_walk=True)
            except CloudFileNotFoundError as e:
                log.debug('File to walk not found %s', e)

            self.state.storage_update_data(self._walk_tag, time.time())
            self.need_walk = False

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
                # this event is from a walk, and we're checking to see if the state has changed
                already = self.state.lookup_oid(self.side, event.oid)
                if already:
                    changed = already[self.side].hash != event.hash or already[self.side].path != event.path
                    if not changed:
                        return

            if not event.path:
                if event.prior_oid:
                    log.error("rename from oid_is_path %s without full path", self.provider.name)

                if from_walk:
                    log.error("walk %s without full path", self.provider.name)
                else:
                    self._fill_event_path(event)

            self.state.update(self.side, event.otype, event.oid, path=event.path, hash=event.hash,
                              exists=event.exists, prior_oid=event.prior_oid)
            self.state.storage_commit()

    def _fill_event_path(self, event):
        # certain providers have "expensive path getting"
        # it's possible we don't need to get the path in all cases
        # the most obvious example is a "delete" event
        # we should investigate better ways of doing this to save api hits

        state = self.state.lookup_oid(self.side, event.oid)
        if state:
            # other events can get paths from cache
            event.path = event.path or state[self.side].path

        if not event.path:
            info = self.provider.info_oid(event.oid)
            if info:
                event.path = info.path
                event.otype = info.otype
                event.hash = info.hash

    def stop(self, forever=True):
        super().stop(forever=forever)
