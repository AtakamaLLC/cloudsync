"""
The registry maintains a map of provider classes by name.
"""


import sys


__all__ = ["create_provider", "get_provider"]


providers = {}


def register_provider(prov):
    providers[prov.name] = prov


def discover_providers():
    for m in sys.modules:
        mod = sys.modules[m]
        if hasattr(mod, "__cloudsync__"):
            if mod.__cloudsync__.name not in providers:             # type: ignore
                register_provider(mod.__cloudsync__)                # type: ignore


def get_provider(name):
    if name not in providers:
        discover_providers()

    if name not in providers:
        raise RuntimeError("%s not a registered provider, maybe you forgot to import cloudsync_%s" % (name, name))

    return providers[name]


def create_provider(name, *args, **kws):
    return get_provider(name)(*args, *kws)


def known_providers():
    discover_providers()
    return list(providers.keys())
