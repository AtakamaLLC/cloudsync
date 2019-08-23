import logging
from typing import TYPE_CHECKING, Optional
from dataclasses import dataclass
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


class EventManager(Runnable):
    def __init__(self, provider: "Provider", state: "SyncState", side, sleep=None):
        self.provider = provider
        assert self.provider.connection_id
        self.label = f"{self.provider.name}:{self.provider.connection_id}"
        self.events = Muxer(self.provider.events, restart=self.wait_for_it)
        self.state = state
        self.side = side
        self._sleep = sleep
        self._cursor_tag = self.label + "_cursor"
        self.cursor = self.state.storage_get_cursor(self._cursor_tag)
        if not self.cursor:
            self.cursor = provider.current_cursor
            if self.cursor:
                self.state.storage_update_cursor(self._cursor_tag, self.cursor)
        else:
            log.debug("retrieved existing cursor %s for %s", self.cursor, self.provider.name)

    def wait_for_it(self):
        current_cursor = self.provider.current_cursor
        if current_cursor != self.cursor:
            self.state.storage_update_cursor(self._cursor_tag, current_cursor)
            self.cursor = current_cursor
        if self._sleep:
            import time
            log.debug("events %s sleeping", self.label)
            time.sleep(self._sleep)

    def do(self):
        for event in self.events:
            self.process_event(event)

    def _drain(self):
        # for tests, delete events
        for _ in self.events:
            pass

    def process_event(self, event: Event):
        log.debug("%s got event %s", self.label, event)
        path = event.path
        exists = event.exists
        otype = event.otype

        if not event.path and not self.state.lookup_oid(self.side, event.oid):
            info = self.provider.info_oid(event.oid)
            if info and info.otype != event.otype:
                log.warning("provider %s gave a bad event: %s != %s, using %s", self.provider.name, info.path, event.otype, info.otype)
            if info:
                path = info.path
                otype = info.otype
            else:
                log.debug("ignoring delete of something that can't exist")
                return

        self.state.update(self.side, otype, event.oid, path=path, hash=event.hash, exists=exists, prior_oid=event.prior_oid)
