import logging
from dataclasses import dataclass
from typing import Optional
from .runnable import Runnable
from .muxer import Muxer
from .types import OType

log = logging.getLogger(__name__)

@dataclass
class Event:
    otype: OType                           # fsobject type     (DIRECTORY or FILE)
    oid: str                               # fsobject id
    path: Optional[str]                    # path
    hash: Optional[bytes]                  # fsobject hash     (better name: ohash)
    exists: Optional[bool]
    mtime: Optional[float]

class EventManager(Runnable):
    def __init__(self, provider, state, side):
        self.provider = provider
        self.oid_is_path = provider.oid_is_path
        self.events = Muxer(provider.events, restart=True)
        self.state = state
        self.side = side

    def do(self):
        for event in self.events:
            log.debug("got event %s", event)
            path = event.path
            exists = event.exists
            otype = event.otype

            if self.oid_is_path:
                assert path

            if not event.path and not self.state.lookup_oid(self.side, event.oid):
                info = self.provider.info_oid(event.oid)
                if info.otype != event.otype:
                    log.warning("provider gave a bad event: %s != %s, using %s", info.path, event.otype, info.otype)
                if info:
                    path = info.path
                    otype = info.otype
                else:
                    log.debug("ignoring delete of something that can't exist")
                    continue

            self.state.update(self.side, otype, event.oid, path=path, hash=event.hash, exists=exists, oid_is_path=self.oid_is_path)

