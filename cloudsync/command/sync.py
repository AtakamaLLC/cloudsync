import re
import logging
import json
try:
    import daemon
except ImportError:
    daemon = None

from cloudsync import CloudSync, get_provider, OAuthConfig


log = logging.getLogger()


class CloudURI:     # pylint: disable=too-few-public-methods
    """
    Represents a faux-URI passed on the command line.

    For example: gdrive:/path/to/file
    """
    def __init__(self, uri):
        if ':' in uri:
            m = re.match(r"([^:]+):(.*)", uri)
            if m:
                (prov, path) = m.groups()
        else:
            (prov, path) = ('file', uri)

        self.provider_type = get_provider(prov)
        self.root = path


OAUTH_CONFIG = {
    "gdrive": {
        "id": "918922786103-f842erh49vb7jecl9oo4b5g4gm1eka6v.apps.googleusercontent.com",
        "secret": "F2CdO5YTzX6TfKGlOMDbV1WS",
    }
}


_config = None


def config(args):
    """The global config singleton, parsed from ~/.config/cloudsync"""
    global _config      # pylint: disable=global-statement
    if _config is None:
        try:
            log.info("config : %s", args.config)
            _config = json.load(open(args.config, "r"))
            if _config is None:
                raise ValueError("Invalid json file %s" % args.config)
        except FileNotFoundError:
            log.debug("config not used: %s", args.config)
            _config = {}
    return _config


def get_oauth_config(args, name):
    """Reads oauth config from the global config singleton, or uses the defaults"""
    top = config(args).get("oauth", {})
    oauth = top.get(name, {})
    default = OAUTH_CONFIG.get(name, {})

    for k in ["id", "secret", "host", "ports"]:
        oauth[k] = oauth.get(k, default.get(k, None))

    return OAuthConfig(app_id=oauth["id"], app_secret=oauth["secret"],
                       host_name=oauth["host"], port_range=oauth["ports"])


def do_sync(args):
    """Processes the 'sync' command, which begins syncing two providers from the command line"""
    if args.quiet:
        log.setLevel(logging.ERROR)

    if args.verbose:
        log.setLevel(logging.DEBUG)

    uris = (CloudURI(args.src), CloudURI(args.dest))
    types = [p.provider_type for p in uris]
    _provs = []
    for cls in types:
        if cls.uses_oauth():
            oc = get_oauth_config(args, cls.name)
            log.debug("init %s oauth", cls.name)
            prov = cls(oc)
        else:
            prov = cls()
        _provs.append(prov)

    cred = args.creds

    for prov in _provs:
        try:
            if not args.quiet and not cred:
                cred = prov.authenticate()
            prov.connect(cred)
        except NotImplementedError:
            prov.reconnect()

    provs = (_provs[0], _provs[1])
    roots = (uris[0].root, uris[1].root)

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
