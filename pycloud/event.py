from collections import namedtuple

# def update(self, side, otype, oid, path=None, hash=None, exists=True):
EventBase = namedtuple('EventBase', 'side otype oid path hash exists')


class Event(EventBase):
    REMOTE = "remote"
    LOCAL = "local"




