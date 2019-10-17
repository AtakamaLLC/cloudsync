import sys
import argparse
import msgpack
from .types import IgnoreReason

def do_debug(args):
    if args.state:
        from cloudsync.sync.sqlite_storage import SqliteStorage
        from cloudsync.sync.state import SyncEntry, SyncState
        from unittest.mock import MagicMock

        fake_state = MagicMock()
        fake_state._pretty_time = 0

        if args.json:
            import json
            print("[")

        store = SqliteStorage(args.state)
        tag_comma = ""
        for tag, ent in store.read_all().items():
            if args.json:
                print(tag_comma, '{"tag":"', tag, '","entries":[')
            ent_comma = ""
            for (eid, ser) in ent.items():
                if type(ser) is bytes:
                    ent = SyncEntry(parent=fake_state, otype=None, storage_init=(eid, ser))
                    if args.changed:
                        if not ent[0].changed and not ent[1].changed:
                            continue
                    if ent.ignored != IgnoreReason.NONE and not args.discarded:
                        continue

                    if args.json:
                        d = msgpack.loads(ser, use_list=True, raw=False)

                        def to_json(d):
                            r = d
                            if type(d) is dict:
                                r = {}
                                for k, v in d.items():
                                    r[k] = to_json(v)
                            elif type(d) is list:
                                r = []
                                for v in d:
                                    r.append(to_json(v))
                            elif type(d) is bytes:
                                r = "bytes:" + d.hex()
                            return r
                        d = to_json(d)
                        print(ent_comma, json.dumps(d))
                        ent_comma = ","
                    else:
                        print(ent.pretty())
            if args.json:
                print("]}")
            tag_comma = ","

        if args.json:
            print("]")


def main():
    parser = argparse.ArgumentParser(description='cloudsync - monitor and sync between cloud providers')
    cmds = parser.add_subparsers(title="Commands")
    cmds.metavar = "Commands:"

    debug_sub = cmds.add_parser('debug', help='Debug commands')
    debug_sub.add_argument('-s', '--state', help='Debug state file', action="store")
    debug_sub.add_argument('-c', '--changed', help='Only changed records', action="store_true")
    debug_sub.add_argument('-d', '--discarded', help='Show discarded records', action="store_true")
    debug_sub.add_argument('-j', '--json', help='Output as json', action="store_true")
    debug_sub.set_defaults(func=do_debug)

    args = parser.parse_args()

    print("# args", args.__dict__, file=sys.stderr)

    if "func" not in args:
        parser.print_help(file=sys.stderr)
        sys.exit(1)

    args.func(args)
