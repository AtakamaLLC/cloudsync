"""
The registry maintains a map of provider classes by name.
"""


import sys
from typing import List, Type
import pkg_resources
from cloudsync.provider import Provider

__all__ = ["create_provider", "get_provider", "known_providers", "register_provider"]


providers = {}


def register_provider(prov: Type[Provider]):
    """Add a provider class to the registry"""
    providers[prov.name] = prov


def discover_providers():
    """Loop through imported modules, and autoregister providers, including plugins"""
    for m in sys.modules:
        mod = sys.modules[m]
        if hasattr(mod, "__cloudsync__"):
            if mod.__cloudsync__.name not in providers:             # type: ignore
                register_provider(mod.__cloudsync__)                # type: ignore

    for entry_point in pkg_resources.iter_entry_points('cloudsync.providers'):
        register_provider(entry_point.resolve())


def get_provider(name: str):
    """Get a provider class with the given name"""
    if name not in providers:
        discover_providers()

    if name not in providers:
        raise RuntimeError("%s not a registered provider, maybe you forgot to import cloudsync_%s" % (name, name))

    return providers[name]


def create_provider(name: str, *args, **kws) -> Provider:
    """Construct a provider instance"""
    return get_provider(name)(*args, **kws)


def known_providers() -> List[str]:
    """List all known provider names, sorted order."""
    discover_providers()
    return list(sorted(providers.keys()))
