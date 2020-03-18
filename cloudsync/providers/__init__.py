from ..tests.fixtures.mock_provider import MockProvider
from cloudsync.registry import register_provider

# optionally load support for supported providers
# todo: eventually there will be some factory class

try:
    from .dropbox import DropboxProvider
except Exception as e:
    _ex = e

    def DropboxProvider(*a, **k):           # type: ignore
        raise _ex

    if isinstance(e, ImportError) and "'DropboxProvider'" not in e.msg:
        DropboxProvider.test_instance = lambda: DropboxProvider()
        DropboxProvider.name = "dropbox"
        register_provider(DropboxProvider)

try:
    from .box import BoxProvider
except Exception as e:
    _ex = e

    def BoxProvider(*a, **k):           # type: ignore
        raise _ex

    if isinstance(e, ImportError) and "'BoxProvider'" not in e.msg:
        BoxProvider.test_instance = lambda: BoxProvider()
        BoxProvider.name = "box"
        register_provider(BoxProvider)

try:
    import sys
    from .file import FileSystemProvider
except Exception as e:
    _ex = e

    def FileSystemProvider(*a, **k):           # type: ignore
        raise _ex

    if isinstance(e, ImportError) and "'FileSystemProvider'" not in e.msg:
        FileSystemProvider.test_instance = lambda: FileSystemProvider()
        FileSystemProvider.name = "filesystem"
        register_provider(FileSystemProvider)
