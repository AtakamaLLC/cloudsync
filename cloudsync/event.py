from collections import namedtuple

# def update(self, side, otype, oid, path=None, hash=None, exists=True):
EventBase = namedtuple('EventBase', 'otype oid path hash exists mtime')


class Event(EventBase):
    # TODO: test provider with all of these changed to random strings to confirm the string isn't used explicitly
    # TODO: shoulde EventBase have "source" or "side" (to match the update() params)
    ACTION_CREATE = "create"
    ACTION_RENAME = "rename"
    ACTION_UPDATE = "modify"
    ACTION_DELETE = "delete"

    TYPE_FILE = "file"
    TYPE_DIRECTORY = "directory"




