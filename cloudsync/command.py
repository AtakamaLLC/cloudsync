import os
import argparse
import msgpack

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
            print(tag_comma, '{"tag":"', tag, '","entries":[')
            ent_comma = ""
            for (eid, ser) in ent.items():
                if type(ser) is bytes:
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
                        ent = SyncEntry(parent=fake_state, otype=None, storage_init=(eid, ser))
                        print(ent.pretty())
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
    debug_sub.add_argument('-j', '--json', help='Output as json', action="store_true")
    debug_sub.set_defaults(func=do_debug)

    args = parser.parse_args()

    print("# args", args.__dict__, file=sys.stderr)

    args.func(args)


if __name__ == "__main__":
    import sys
    sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    main()
