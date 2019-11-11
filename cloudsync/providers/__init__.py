from ..tests.fixtures.mock_provider import MockProvider

# optionally load support for supported providers
# todo: eventually there will be some factory class

try:
    from .dropbox import DropboxProvider
except Exception:
    pass

try:
    from .onedrive import OneDriveProvider
except Exception:
    pass

try:
    from .gdrive import GDriveProvider
except Exception:
    pass
