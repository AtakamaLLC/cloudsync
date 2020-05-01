import logging
import json
from typing import Iterable

from unittest.mock import MagicMock

import msgpack

from cloudsync.sync.sqlite_storage import SqliteStorage
from cloudsync.sync.state import SyncEntry, SyncState

from .utils import SubCmd

log = logging.getLogger("cloudsync.command")

class DebugCmd(SubCmd):
    """Debug subcommand"""

    def __init__(self, cmds):
        super().__init__(cmds, 'debug', help='Debug commands')
        self.parser.add_argument('-s', '--state', help='Debug state file', action="store")
        self.parser.add_argument('-c', '--changed', help='Only changed records', action="store_true")
        self.parser.add_argument('-d', '--discarded', help='Show discarded records', action="store_true")
        self.parser.add_argument('-j', '--json', help='Output as json', action="store_true")

    @staticmethod
    def run(args):
        """Implements the 'debug' command, mostly for diagnosing state databases"""
        if args.state:
            fake_state = MagicMock()
            fake_state._pretty_time = 0                                         # pylint: disable=protected-access

            if args.json:
                print("{")

            store = SqliteStorage(args.state)
            tags = set()
            for tag, _ in store.read_all().items():
                tags.add(tag)

            first = True
            for tag in tags:
                logging.getLogger().setLevel(logging.CRITICAL)
                ss = SyncState((MagicMock(), MagicMock()), store, tag)
                logging.getLogger().setLevel(logging.INFO)
                if args.json:
                    output_json_for_tag(args, ss, tag, first)
                else:
                    if ss.get_all(discarded=args.discarded):
                        print("****", tag, "****")
                        print(ss.pretty_print())

                if args.json:
                    print("]")
                first = False

            if args.json:
                print("}")

cmd_class = DebugCmd

def to_jsonable(d):
    """Make something jsonable, for pretty printing reasons."""
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


def output_json_for_tag(args, ss, tag, first):
    """Outputs json for a given state tag, for debugging only"""
    stuff: Iterable[SyncEntry]
    if args.changed:
        stuff = ss.changes
    else:
        stuff = ss.get_all(discarded=args.discarded)

    if not stuff:
        return

    print("," if not first else "", '"%s":[' % tag)
    ent_comma = ""
    se: SyncEntry
    for se in stuff:
        if not args.discarded:
            if se.is_conflicted or se.is_discarded:
                continue
        ser = se.serialize()
        d = msgpack.loads(ser, use_list=True, raw=False)

        d = to_jsonable(d)
        print(ent_comma, json.dumps(d))
        ent_comma = ","

