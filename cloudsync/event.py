import logging
from typing import TYPE_CHECKING, Optional, Generator
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


def cursor_tag(provider_name, connection_uid):
    return "%s_%s_cursor" % (provider_name, connection_uid)


class EventManager(Runnable):
    def __init__(self, provider: "Provider", state: "SyncState", side, sleep=None):
        self.provider = provider
        self.events = Muxer(self.provider_events, restart=self.waitforit, wait_for_drain=True)
        self.state = state
        self.side = side
        self._sleep = sleep
        self.new_cursor = None
        self._cursor_tag = cursor_tag(provider.name, provider.uid)
        self.cursor = self.state.storage_get_cursor(self._cursor_tag)
        if not self.cursor:
            self.cursor = provider.cursor
            if self.cursor:
                self.state.storage_update_cursor(self._cursor_tag, self.cursor)

    def provider_events(self) -> Generator["Event", None, None]:
        for event in self.provider.events():
            yield event
            if event.new_cursor:
                self.new_cursor = event.new_cursor

    def waitforit(self):
        if self.new_cursor:
            self.state.storage_update_cursor(self._cursor_tag, self.new_cursor)
            self.new_cursor = None
        if self._sleep:
            import time
            log.debug("events %s sleeping", self.provider.name)
            time.sleep(self._sleep)

    def do(self):
        for event in self.events:
            self.process_event(event)

    def process_event(self, event: Event):
        log.debug("got event %s", event)
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
