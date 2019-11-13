from ..tests.fixtures.mock_provider import MockProvider

# optionally load support for supported providers
# todo: eventually there will be some factory class

try:
    from .dropbox import DropboxProvider
except Exception as e:
    ex = e

    def DropboxProvider(*a, **k):           # type: ignore
        raise ex

try:
    from .onedrive import OneDriveProvider
except Exception as e:
    ex = e

    def OneDriveProvider(*a, **k):          # type: ignore
        raise ex

try:
    from .gdrive import GDriveProvider
except Exception as e:
    ex = e

    def GDriveProvider(*a, **k):            # type: ignore
        raise ex
