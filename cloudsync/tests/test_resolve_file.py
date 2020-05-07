# pylint: disable=missing-docstring

import os
import io

from cloudsync.sync.manager import ResolveFile, SyncEntry, FILE, LOCAL

from requests_toolbelt import MultipartEncoder
from unittest.mock import MagicMock, patch
import pytest


@pytest.fixture(name="rfile")
def _rfile(mock_provider, tmp_path):
    ent = SyncEntry(MagicMock(), FILE)

    info = mock_provider.create("/path", io.BytesIO(b"hello"))

    ent[LOCAL].path = info.path
    ent[LOCAL].oid = info.oid

    ent[LOCAL].temp_file = str(tmp_path / "tmp")

    rf = ResolveFile(ent[LOCAL], mock_provider)

    yield (rf, ent[LOCAL].temp_file)

def test_rfile(rfile):
    rf, temp_file = rfile
    # this will raise an odd error of rf doesnt' support len(rf)

    MultipartEncoder(
        fields={'field0': 'value', 'field1': 'value',
                'field2': ('filename', rf, 'text/plain')}
        )

    assert open(temp_file).read() == "hello"

def test_rfile_ops(rfile):
    rf, _ = rfile
    assert rf.read() == b"hello"
    assert rf.tell() == 5
    rf.seek(0, 0)
    assert rf.read() == b"hello"


def test_rfile_fail(rfile):
    rf, temp_file = rfile

    with pytest.raises(ZeroDivisionError):
        with patch.object(rf.provider, "download", side_effect=lambda *a, **k: 4/0):
            rf.download()

    assert not os.path.exists(temp_file)


def test_rfile_fail_badpath(mock_provider):
    ent = SyncEntry(MagicMock(), FILE)

    info = mock_provider.create("/path", io.BytesIO(b"hello"))

    ent[LOCAL].path = info.path
    ent[LOCAL].oid = info.oid

    ent[LOCAL].temp_file = str("/this/path/is/missing")

    rf = ResolveFile(ent[LOCAL], mock_provider)

    with pytest.raises(FileNotFoundError):
        with patch.object(rf.provider, "download", side_effect=lambda *a, **k: 4/0):
            rf.download()

