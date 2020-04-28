import importlib

from cloudsync.registry import register_provider
from ..tests.fixtures.mock_provider import MockProvider

# optionally load support for supported providers
# todo: eventually there will be some factory class

def _local_import(class_name, module, short_name):
    try:
        mod = importlib.import_module(module, __name__)
        ret = getattr(mod, class_name)
    except Exception as e:
        _ex = e

        class Fake(MockProvider):
            name = short_name
            def __init__(self, *a, **k):  # pylint: disable=super-init-not-called
                raise _ex

        # syntax errors and other stuff propagates immediately
        if not isinstance(e, ImportError):
            raise
       
        # other errors are allowed, unless you use it
        ret = Fake
    
    register_provider(ret)
    return ret

DropboxProvider = _local_import("DropboxProvider", ".dropbox", "dropbox")
FileSystemProvider = _local_import("FileSystemProvider", ".filesystem", "filesystem")
BoxProvider = _local_import("BoxProvider", ".box", "box")
