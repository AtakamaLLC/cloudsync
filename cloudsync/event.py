import logging
import time
from typing import TYPE_CHECKING, Optional, Callable
from dataclasses import dataclass
from pystrict import strict
from .exceptions import CloudTemporaryError, CloudDisconnectedError, CloudCursorError, CloudTokenError
from .runnable import Runnable
from .muxer import Muxer
from .types import OType

if TYPE_CHECKING:
    from cloudsync.sync import SyncState
    from cloudsync import Provider

log = logging.getLogger(__name__)


@dataclass
class Event:
    otype: OType                           # fsobject type     (DIRECTORY or FILE)
    oid: str                               # fsobject id
    path: Optional[str]                    # path
    hash: Optional[bytes]                  # fsobject hash     (better name: ohash)
    exists: Optional[bool]
    mtime: Optional[float] = None
    prior_oid: Optional[str] = None        # path basesd systems use this on renames
    new_cursor: Optional[str] = None


@strict             # pylint: disable=too-many-instance-attributes
class EventManager(Runnable):
    def __init__(self, provider: "Provider", state: "SyncState", side: int, walk_root: Optional[str] = None, reauth: Callable[[], None] = None):
        log.debug("provider %s, root %s", provider.name, walk_root)
        self.provider = provider
        assert self.provider.connection_id
        self.label = f"{self.provider.name}:{self.provider.connection_id}"
        self.events = Muxer(provider.events, restart=True)
        self.state = state
        self.side = side
        self._cursor_tag: str = self.label + "_cursor"

        self.walk_one_time = None
        self._walk_tag: str = None
        self.cursor = self.state.storage_get_data(self._cursor_tag)

        if self.cursor is not None:
            log.debug("retrieved existing cursor %s for %s", self.cursor, self.provider.name)
            try:
                self.provider.current_cursor = self.cursor
            except CloudCursorError as e:
                log.exception("Cursor error... resetting cursor. %s", e)
                self.cursor = None

        if walk_root:
            self._walk_tag = self.label + "_walked_" + walk_root
            if self.cursor is None or self.state.storage_get_data(self._walk_tag) is None:
                self.walk_one_time = walk_root

        if self.cursor is None:
            self.cursor = provider.current_cursor
            if self.cursor is not None:
                self.state.storage_update_data(self._cursor_tag, self.cursor)

        self.min_backoff = provider.default_sleep / 10
        self.max_backoff = provider.default_sleep * 4
        self.mult_backoff = 2

        self.reauthenticate = reauth or self.__reauth

    def __reauth(self):
        self.provider.connect(self.provider.authenticate())

    def forget(self):
        if self._walk_tag is not None:
            self.state.storage_delete_tag(self._walk_tag)
        if self._cursor_tag is not None:
            self.state.storage_delete_tag(self._cursor_tag)

    def do(self):
        self.events.shutdown = False
        try:
            try:
                self._do_unsafe()
            except CloudTemporaryError as e:
                log.warning("temporary error %s[%s] in event watcher", type(e), e)
                self.backoff()
            except CloudDisconnectedError:
                self.backoff()
                try:
                    log.info("reconnect to %s", self.provider.name)
                    self.provider.reconnect()
                except CloudDisconnectedError as e:
                    log.info("can't reconnect to %s: %s", self.provider.name, e)
            except CloudCursorError as e:
                log.exception("Cursor error... resetting cursor. %s", e)
                self.provider.current_cursor = self.provider.latest_cursor
                self._save_current_cursor()
        except CloudTokenError:
            # this is separated from the main block because
            # it can be raised during reconnect in the exception handler and in do_unsafe
            self.reauthenticate()

    def _do_unsafe(self):
        if self.walk_one_time:
            log.debug("walking all %s/%s files as events, because no working cursor on startup",
                      self.provider.name, self.walk_one_time)
            for event in self.provider.walk(self.walk_one_time):
                self.process_event(event, from_walk=True)
            self.state.storage_update_data(self._walk_tag, time.time())
            self.walk_one_time = None

        for event in self.events:
            if not event:
                log.error("%s got BAD event %s", self.label, event)
                continue
            self.process_event(event)

        self._save_current_cursor()

    def _save_current_cursor(self):
        current_cursor = self.provider.current_cursor

        if current_cursor != self.cursor:
            self.state.storage_update_data(self._cursor_tag, current_cursor)
            self.cursor = current_cursor

    def _drain(self):
        # for tests, delete events
        for _ in self.events:
            pass

    def process_event(self, event: Event, from_walk=False):
        with self.state.lock:
            log.debug("%s got event %s", self.label, event)
            path = event.path
            exists = event.exists
            otype = event.otype
            ehash = event.hash
            info = None

            if from_walk or not event.path and not self.state.lookup_oid(self.side, event.oid):
                info = self.provider.info_oid(event.oid)
                if info:
                    if info.otype != event.otype:
                        log.warning("provider %s gave a bad event: %s != %s, using %s",
                                    self.provider.name, info.path, event.otype, info.otype)
                    path = info.path
                    otype = info.otype
                    ehash = info.hash

            if from_walk:
                # this event is from a walk, and we're checking to see if the state has changed
                already = self.state.lookup_oid(self.side, event.oid)
                if already:
                    changed = already[self.side].hash != ehash or already[self.side].path != path
                    if not changed:
                        return

            self.state.update(self.side, otype, event.oid, path=path, hash=ehash,
                              exists=exists, prior_oid=event.prior_oid)
            self.state.storage_commit()

    def stop(self, forever=True):
        if forever:
            self.events.shutdown = True
        super().stop(forever=forever)
