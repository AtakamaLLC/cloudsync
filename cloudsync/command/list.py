import sys

import logging
import datetime

from typing import Union

from cloudsync.utils import debug_sig

from .utils import CloudURI, SubCmd

log = logging.getLogger()

def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Y', suffix)

class ListCmd(SubCmd):
    """List command.   Just connects and lists the files at a provider path.

    Useful for testing a connection.
    """

    def __init__(self, cmds):
        """Command line args for list."""

        super().__init__(cmds, 'list', help='List files at provider')
        self.parser.add_argument('prov', help='Provider uri')
        self.parser.add_argument('-l', "--long", help='Long listing', action='store_true')
        self.parser.add_argument('-n', "--namespaces", help='List namespaces', action='store_true')

        self.common_sync_args()

    @staticmethod
    def run(args):
        """Processes the 'list' command, which begins syncing two providers from the command line"""
        if args.quiet:
            log.setLevel(logging.ERROR)

        uri = CloudURI(args.prov)
        prov = uri.provider_instance(args)

        if args.namespaces:
            ns = prov.list_ns()
            if ns is None:
                print("Namspaces not supported.", sys.stderr)
            else:
                for n in prov.list_ns():
                    print(n)
            return

        for f in prov.listdir_path(uri.path):
            if args.long:
                print("%-40s %-20s %8s %s" % ("name", "time", "size", "oid"))
                print("%-40s %-20s %8s %s" % ("----", "----", "----", "---"))
                ftime: Union[str, float] = f.mtime or 0
                if not isinstance(ftime, str):
                    mtime = datetime.datetime.fromtimestamp(ftime)
                    ftime = datetime.datetime.strftime(mtime, "%Y%M%D %H:%M:%S")

                print("%-40s %-20s %8s %s" % (f.name, ftime, sizeof_fmt(f.size), debug_sig(f.oid)))
            else:
                print(f.name)

cmd_class = ListCmd
