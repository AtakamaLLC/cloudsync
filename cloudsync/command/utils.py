import os
import re
import logging
import json
import argparse
import abc
from typing import Optional

from cloudsync import get_provider, known_providers, OAuthConfig, Provider, Creds, CloudNamespaceError

log = logging.getLogger()

PROVIDER_ALIASES = {
    "file" : "filesystem",
}

def cli_providers():
    return sorted(p for p in known_providers() if not p.startswith("test") and not p.startswith("mock_"))

class SubCmd(abc.ABC):
    """Base class for sub commands"""

    def __init__(self, main, name, help):               # pylint: disable=redefined-builtin
        self.parser: argparse.ArgumentParser = main.add_parser(
                name,
                help=help,
                formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    def common_sync_args(self):
        """Add common sync config args."""
        default_config = os.path.expanduser("~/.config/cloudsync/config")
        default_creds = os.path.expanduser("~/.config/cloudsync/creds")

        self.parser.add_argument('-C', '--config', help='Read config from file', action="store", default=default_config)
        # toto: support two schemes: file:/path, keyring:cloudsync
        self.parser.add_argument('-R', '--creds', help='Read/save creds from file', action="store", default=default_creds)
        self.parser.add_argument('-q', '--quiet', help='Quiet mode, no interactive auth', action="store_true")

        self.parser.epilog = f"""
    Supported providers: {cli_providers()}
        """

    @abc.abstractmethod
    def run(self, args: argparse.Namespace):
        ...

class FauxURI:     # pylint: disable=too-few-public-methods
    """
    Represents a faux-URI passed on the command line.

    For example: foo:bar
    """
    def __init__(self, uri):
        (method, path) = ('file', uri)
        if ':' in uri:
            # this enhrines that provider names must be 2 or more characters
            # and it protects us from seeing c:/whatever as a provider
            m = re.match(r"([^:]{2,}):(.*)", uri)
            if m:
                (method, path) = m.groups()

        self.method = method
        self.path = path

class CloudURI(FauxURI):     # pylint: disable=too-few-public-methods
    """
    Represents a faux-cloud-URI passed on the command line.

    For example: gdrive:/path/to/file
                 onedrive@team/namespace:path/to/file
    """
    def __init__(self, uri):
        super().__init__(uri)

        self.namespace = ""
        namespace = re.match(r"(.*)@(.*)", self.method)
        if namespace:
            (self.method, self.namespace) = namespace.groups()

        if self.method in PROVIDER_ALIASES:
            self.method = PROVIDER_ALIASES[self.method]
        if self.method not in known_providers():
            raise ValueError("Unknown provider %s, try pip install cloudsync[%s] or pip install cloudsync-%s" % (self.method, self.method, self.method))
        self.provider_type = get_provider(self.method)

    def _set_namespace(self, provider: Provider):
        if provider.name == "filesystem":
            # todo: this is a crappy hack because we don't initialze providers with the root oid or path
            # once that's done, this can go away
            provider.namespace_id = self.path
            self.path = "/"
        elif self.namespace:
            # lookup namespace by name
            namespace = next((ns for ns in provider.list_ns() if ns.name == self.namespace), None)
            if not namespace:
                raise CloudNamespaceError(f"unknown namespace: {self.namespace}")
            provider.namespace = namespace

    def provider_instance(self, args, *, connect=True) -> Provider:
        """Given command-line args, construct a provider object, and connect it."""

        cls = self.provider_type

        creds = None

        if cls.uses_oauth():
            oc = get_oauth_config(args, cls.name, args.creds)
            log.debug("init %s oauth", cls.name)
            prov = cls(oc)
            creds = oc.get_creds()
            if not args.quiet and not creds and connect:
                creds = prov.authenticate()

            if creds:
                prov.set_creds(creds)

            if connect:
                prov.connect(creds)
        else:
            prov = cls()
            if cls.name.startswith("mock_"):
                prov.set_creds({"fake" : "creds"})
            prov.reconnect()

        self._set_namespace(prov)
        return prov


# TOOD: better documentation on how to get your own one of these
OAUTH_CONFIG = {
    "gdrive": {
        "id": "918922786103-f842erh49vb7jecl9oo4b5g4gm1eka6v.apps.googleusercontent.com",
        "secret": "F2CdO5YTzX6TfKGlOMDbV1WS",
    },
    "onedrive": {
        "id": "797a365f-772d-421f-a3fe-7b55ab6defa4",
        "secret": "",
    }
}

_config = None


def config(args):
    """The global config singleton, parsed from ~/.config/cloudsync"""
    global _config      # pylint: disable=global-statement
    if _config is None:
        try:
            log.debug("config : %s", args.config)
            _config = json.load(open(args.config, "r"))
        except FileNotFoundError:
            log.debug("config not used: %s", args.config)
            _config = {}
    return _config


class CliOAuthConfig(OAuthConfig):
    """OAuth config for command line.   Writes to local creds file or keyring."""
    def __init__(self, *ar, prov_name, save_uri, **kw):
        self.save: Optional[FauxURI] = save_uri and FauxURI(save_uri)
        self.prov = prov_name
        self.creds: Creds = {}

        if self.save:
            if self.save.method != "file":
                raise ValueError("Unsupported creds save method: %s" % self.save.method)

            try:
                log.debug("load creds %s", self.save.path)
                with open(self.save.path) as f:
                    self.creds = json.load(f)
            except FileNotFoundError:
                pass

        super().__init__(*ar, **kw)

    def get_creds(self):
        if not self.save:
            return None

        return self.creds.get(self.prov, None)

    def creds_changed(self, creds):
        if not self.save:
            super().creds_changed(creds)
            return

        try:
            was = os.umask(0o77)
            self.creds.update({self.prov: creds})
            os.makedirs(os.path.dirname(self.save.path), mode=0o700, exist_ok=True)
            with open(self.save.path, "w") as f:
                json.dump(self.creds, f)
        finally:
            os.umask(was)


def generic_oauth_config(name):
    return get_oauth_config(None, name, None)


def get_oauth_config(args, name, save_uri):
    """Reads oauth config from the global config singleton, or uses the defaults"""
    if args:
        top = config(args).get("oauth", {})
        oauth = top.get(name, {})
    else:
        oauth = {}
    default = OAUTH_CONFIG.get(name, {})

    for k in ["id", "secret", "host", "ports"]:
        oauth[k] = oauth.get(k, default.get(k, None))

    return CliOAuthConfig(prov_name=name, save_uri=save_uri, app_id=oauth["id"], app_secret=oauth["secret"],
                          host_name=oauth["host"], port_range=oauth["ports"])


def get_providers(args, uris):
    """Given command args and a pair of CloudURI objects, return provider objects."""
    _provs = []
    for uri in uris:
        prov = uri.provider_instance(args)
        _provs.append(prov)
    return _provs
