from collections import namedtuple

Event = namedtuple('EventBase', 'otype oid path hash exists mtime')
