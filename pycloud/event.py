from collections import namedtuple

from .runnable import Runnable

EventBase = namedtuple('EventBase', 'type path oid hash exists')


class Event(EventBase):
    REMOTE = "remote"
    LOCAL = "local"

class EventManager(Runnable):
    def do(self):  # One iteration of the loop
        # get events
        # update the state
        pass
