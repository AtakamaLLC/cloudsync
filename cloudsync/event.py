import logging
import time
from typing import TYPE_CHECKING, Optional
from dataclasses import dataclass
from .exceptions import CloudTemporaryError, CloudDisconnectedError
from .runnable import Runnable
from .muxer import Muxer
from .types import OType
from . import strict

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
    def __init__(self, provider: "Provider", state: "SyncState", side: int, walk_root: str = None):
        log.debug("provider %s, root %s", provider.name, walk_root)
        self.provider = provider
        assert self.provider.connection_id
        self.label = f"{self.provider.name}:{self.provider.connection_id}"
        self.events = Muxer(provider.events, restart=True)
        self.state = state
        self.side = side
        self.shutdown = False
        self._cursor_tag = self.label + "_cursor"
        self.cursor = self.state.storage_get_cursor(self._cursor_tag)
        self.walk_root = None

        self.min_backoff = provider.default_sleep / 10
        self.max_backoff = provider.default_sleep * 4
        self.mult_backoff = 2
        self.backoff = self.min_backoff

        if not self.cursor:
            self.walk_root = walk_root
            self.cursor = provider.current_cursor
            if self.cursor:
                self.state.storage_update_cursor(self._cursor_tag, self.cursor)
        else:
            log.debug("retrieved existing cursor %s for %s", self.cursor, self.provider.name)
# TODO!!!!            provider.current_cursor = self.cursor

    def do(self):
        try:
            if self.walk_root:
                log.debug("walking all %s/%s files as events, because no working cursor on startup",
                          self.provider.name, self.walk_root)
                for event in self.provider.walk(self.walk_root):
                    self.process_event(event)
                self.walk_root = None
                self.backoff = self.min_backoff

            for event in self.events:
                if not event:
                    log.error("%s got BAD event %s", self.label, event)
                    continue
                self.process_event(event)

            current_cursor = self.provider.current_cursor

            if current_cursor != self.cursor:
                self.state.storage_update_cursor(self._cursor_tag, current_cursor)
                self.cursor = current_cursor
        except CloudDisconnectedError:
            try:
                time.sleep(self.backoff)
                self.backoff = min(self.backoff * self.mult_backoff, self.max_backoff)
                log.info("reconnect to %s", self.provider.name)
                # TODO: this will pop an oauth if there is a CloudTokenError on reconnect. create a mechanism
                #   to pass authentication problems to the consumer and allow them to decide what to do
                self.provider.reconnect()
            except Exception as e:
                log.error("can't reconnect to %s: %s", self.provider.name, e)

    def _drain(self):
        # for tests, delete events
        for _ in self.events:
            pass

    def process_event(self, event: Event):
        with self.state.lock:
            log.debug("%s got event %s", self.label, event)
            path = event.path
            exists = event.exists
            otype = event.otype

            if not event.path and not self.state.lookup_oid(self.side, event.oid):
                try:
                    info = self.provider.info_oid(event.oid)
                    if info:
                        if info.otype != event.otype:
                            log.warning("provider %s gave a bad event: %s != %s, using %s",
                                        self.provider.name, info.path, event.otype, info.otype)
                        path = info.path
                        otype = info.otype
                except CloudTemporaryError:
                    pass

            self.state.update(self.side, otype, event.oid, path=path, hash=event.hash,
                              exists=exists, prior_oid=event.prior_oid)

    def stop(self):
        self.events.shutdown = True
        self.shutdown = True
        super().stop()
