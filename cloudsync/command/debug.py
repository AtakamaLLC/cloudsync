import logging
import json
from typing import Iterable

from unittest.mock import MagicMock

import msgpack

from cloudsync.sync.sqlite_storage import SqliteStorage
from cloudsync.sync.state import SyncEntry, SyncState

log = logging.getLogger()


def to_jsonable(d):
    r = d
    if type(d) is dict:
        r = {}
        for k, v in d.items():
            r[k] = to_jsonable(v)
    elif type(d) is list:
        r = []
        for v in d:
            r.append(to_jsonable(v))
    elif type(d) is bytes:
        r = "bytes:" + d.hex()
    return r


def do_debug(args):
    if args.state:
        fake_state = MagicMock()
        fake_state._pretty_time = 0                                         # pylint: disable=protected-access

        if args.json:
            print("{")

        store = SqliteStorage(args.state)
        tags = set()
        for tag, _ in store.read_all().items():
            tags.add(tag)

        tag_comma = ""
        for tag in tags:
            logging.getLogger().setLevel(logging.CRITICAL)
            ss = SyncState((MagicMock(), MagicMock()), store, tag)
            logging.getLogger().setLevel(logging.INFO)
            if args.json:
                stuff: Iterable[SyncEntry]
                if args.changed:
                    stuff = ss.changes
                else:
                    stuff = ss.get_all(discarded=args.discarded)

                if not stuff:
                    continue

                print(tag_comma, '"%s":[' % tag)
                tag_comma = ","
                ent_comma = ""
                se: SyncEntry
                for se in stuff:
                    ser = se.serialize()
                    d = msgpack.loads(ser, use_list=True, raw=False)

                    d = to_jsonable(d)
                    print(ent_comma, json.dumps(d))
                    ent_comma = ","
            else:
                if ss.get_all(discarded=args.discarded):
                    print("****", tag, "****")
                    print(ss.pretty_print())

            if args.json:
                print("]")

        if args.json:
            print("}")

