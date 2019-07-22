from collections import namedtuple

EventBase = namedtuple('EventBase', 'type path oid hash exists')


class Event(EventBase):
    REMOTE = "remote"
    LOCAL = "local"



