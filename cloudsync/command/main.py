import sys
import argparse

from .debug import do_debug


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
