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
            self.state.update(self.side, event.otype, event.oid, path=event.path, hash=event.hash, exists=event.exists)

