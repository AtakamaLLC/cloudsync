from .runnable import Runnable

import logging
log = logging.getLogger(__name__)

class EventManager(Runnable):
    def __init__(self, provider, state, side):
        self.provider = provider
        self.state = state
        self.side = side

    def do(self):
        for event in self.provider.events():
            log.debug("got event %s", event)
            self.state.update(self.side, event.otype, event.oid, path=event.path, hash=event.hash, exists=event.exists)
