from cloudsync.registry import register_provider
from ..tests.fixtures.mock_provider import MockProvider

# optionally load support for supported providers
# todo: eventually there will be some factory class

try:
    from .dropbox import DropboxProvider
except Exception as e:
    _ex = e

    def DropboxProvider(*a, **k):           # type: ignore
        raise _ex

    if isinstance(e, ImportError) and "'DropboxProvider'" not in str(e):
        DropboxProvider.test_instance = lambda: DropboxProvider()   # type: ignore  # pylint: disable=unnecessary-lambda
        DropboxProvider.name = "dropbox"
        register_provider(DropboxProvider)

try:
    from .box import BoxProvider
except Exception as e:
    _ex = e

    def BoxProvider(*a, **k):           # type: ignore
        raise _ex

    if isinstance(e, ImportError) and "'BoxProvider'" not in str(e):
        BoxProvider.test_instance = lambda: BoxProvider()   # type: ignore  # pylint: disable=unnecessary-lambda
        BoxProvider.name = "box"
        register_provider(BoxProvider)

try:
    import sys
    from .file import FileSystemProvider
except Exception as e:
    _ex = e

    def FileSystemProvider(*a, **k):           # type: ignore
        raise _ex

    if isinstance(e, ImportError) and "'FileSystemProvider'" not in str(e):
        FileSystemProvider.test_instance = lambda: FileSystemProvider()   # type: ignore  # pylint: disable=unnecessary-lambda
        FileSystemProvider.name = "filesystem"
        register_provider(FileSystemProvider)
