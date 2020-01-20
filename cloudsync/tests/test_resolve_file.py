import io

from cloudsync.sync.manager import ResolveFile, SyncEntry, FILE, LOCAL

from requests_toolbelt import MultipartEncoder
from unittest.mock import MagicMock


def test_rfile(mock_provider, tmp_path):
    ent = SyncEntry(MagicMock(), FILE)

    info = mock_provider.create("/path", io.BytesIO(b"hello"))

    ent[LOCAL].path = info.path
    ent[LOCAL].oid = info.oid

    ent[LOCAL].temp_file = str(tmp_path / "tmp")

    rf = ResolveFile(ent[LOCAL], mock_provider)

    # this will raise an odd error of rf doesnt' support len(rf)

    MultipartEncoder(
        fields={'field0': 'value', 'field1': 'value',
                'field2': ('filename', rf, 'text/plain')}
        )
