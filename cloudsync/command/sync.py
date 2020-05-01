import os
import sys
import logging

try:
    import daemon
except ImportError:
    daemon = None

from cloudsync import CloudSync, SqliteStorage

from .utils import CloudURI, get_providers, log, SubCmd

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
        default_state = os.path.expanduser("~/.config/cloudsync/state")
        self.parser.add_argument('-S', '--statedb', help='State file path', action="store", default=default_state)

    @staticmethod
    def run(args):
        """Processes the 'sync' command, which begins syncing two providers from the command line"""
        if args.quiet:
            log.setLevel(logging.ERROR)

        uris = (CloudURI(args.src), CloudURI(args.dest))
        _provs = get_providers(args, uris)

        provs = (_provs[0], _provs[1])
        roots = (uris[0].path, uris[1].path)

        storage = SqliteStorage(args.statedb)

        cs = CloudSync(provs, roots, storage=storage)

        # todo: providers should let cs know that cursors shouldn't be stored/used later
        for side, uri in enumerate(uris):
            if uri.method == "filesystem":
                cs.walk(side, uri.path)

        done = None
        if args.onetime:
            done = lambda: not cs.busy

        if args.daemon:
            if not daemon:
                raise NotImplementedError("daemon mode is not available")
            with daemon.DaemonContext(stderr=sys.stderr, stdout=sys.stdout):
                cs.start(until=done)
                cs.wait()
        else:
            cs.start(until=done)
            cs.wait()

cmd_class = SyncCmd
