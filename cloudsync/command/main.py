import os
import sys
import argparse
import logging

from .debug import do_debug
from .sync import do_sync

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def main():
    """cloudsync command line main"""
    parser = argparse.ArgumentParser(description='cloudsync - monitor and sync between cloud providers')
    cmds = parser.add_subparsers(title="Commands")
    cmds.metavar = "Commands:"

    default_config = os.path.expanduser("~/.config/cloudsync")

    debug_sub = cmds.add_parser('debug', help='Debug commands')
    debug_sub.add_argument('-s', '--state', help='Debug state file', action="store")
    debug_sub.add_argument('-c', '--changed', help='Only changed records', action="store_true")
    debug_sub.add_argument('-d', '--discarded', help='Show discarded records', action="store_true")
    debug_sub.add_argument('-j', '--json', help='Output as json', action="store_true")
    debug_sub.set_defaults(func=do_debug)

    sync_sub = cmds.add_parser('sync', help='Sync commands')
    sync_sub.add_argument('src', help='Provider uri 1')
    sync_sub.add_argument('dest', help='Provider uri 2')
    sync_sub.add_argument('-q', '--quiet', help='Quiet mode, no interactive auth for provider', action="store_true")
    sync_sub.add_argument('-v', '--verbose', help='More verbose logging', action="store_true")
    sync_sub.add_argument('-c', '--creds', help='Read credentials from a file, instead of authorizing', action="store")
    sync_sub.add_argument('-o', '--onetime', help='Just walk/copy files once and exit', action="store_true")
    sync_sub.add_argument('-D', '--daemon', help='Run in the background', action="store_true")
    sync_sub.add_argument('-C', '--config', help='Use this config file', action="store", default=default_config)
    sync_sub.set_defaults(func=do_sync)

    args = parser.parse_args()

    print("# args", args.__dict__, file=sys.stderr)

    if "func" not in args:
        parser.print_help(file=sys.stderr)
        sys.exit(1)

    try:
        args.func(args)
    except Exception as e:
        print("Error ", e, file=sys.stderr)
