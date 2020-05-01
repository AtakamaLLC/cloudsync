import os
import logging

try:
    import daemon
except ImportError:
    daemon = None

from cloudsync import CloudSync

from .utils import CloudURI, get_providers, log, SubCmd

# all files written as user-only
os.umask(0o77)


class SyncCmd(SubCmd):
    """Sync subcommand: primary method of spinning up a sync."""

    def __init__(self, cmds):
        """Command line args for sync."""

        super().__init__(cmds, "sync", "Sync command")

        self.common_sync_args()

        self.parser.add_argument('src', help='Provider uri 1')
        self.parser.add_argument('dest', help='Provider uri 2')
        self.parser.add_argument('-o', '--onetime', help='Just walk/copy files once and exit', action="store_true")
        self.parser.add_argument('-D', '--daemon', help='Run in the background', action="store_true")

    @staticmethod
    def run(args):
        """Processes the 'sync' command, which begins syncing two providers from the command line"""
        if args.quiet:
            log.setLevel(logging.ERROR)

        uris = (CloudURI(args.src), CloudURI(args.dest))
        _provs = get_providers(args, uris)

        provs = (_provs[0], _provs[1])
        roots = (uris[0].path, uris[1].path)

        cs = CloudSync(provs, roots)

        done = None
        if args.onetime:
            done = lambda: not cs.busy

        if args.daemon:
            if not daemon:
                raise NotImplementedError("daemon mode is not available")
            with daemon.DaemonContext():
                cs.start(until=done)
        else:
            cs.start(until=done)
            cs.wait()

cmd_class = SyncCmd
