import logging
from collections import namedtuple

from .runnable import Runnable

log = logging.getLogger(__name__)

Event = namedtuple('EventBase', 'otype oid path hash exists mtime')

class EventManager(Runnable):
    def __init__(self, provider, state, side):
        self.provider = provider
        self.state = state
        self.side = side

    def do(self):
        for event in self.provider.events():
            log.debug("got event %s", event)
            path = event.path
            exists = event.exists
            otype = event.otype

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

            self.state.update(self.side, otype, event.oid, path=path, hash=event.hash, exists=exists)

