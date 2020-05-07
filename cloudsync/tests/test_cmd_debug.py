# pylint: disable=missing-docstring

import logging
import json

from unittest.mock import MagicMock

import pytest

from cloudsync.utils import NamedTemporaryFile
from cloudsync.command.debug import DebugCmd

from cloudsync import SqliteStorage, SyncState, LOCAL, FILE, IgnoreReason

log = logging.getLogger()


@pytest.mark.parametrize("arg_json", [True, False], ids=["json", "nojson"])
@pytest.mark.parametrize("arg_discard", [True, False], ids=["discarded", "nodiscarded"])
@pytest.mark.parametrize("arg_changed", [True, False], ids=["changed", "unchanged"])
def test_debug_mode(capsys, arg_json, arg_discard, arg_changed):
    providers = (MagicMock(), MagicMock())

    tf = NamedTemporaryFile(mode=None)
    try:
        storage = SqliteStorage(tf.name)
        state = SyncState(providers, storage, tag="whatever")
        state.update(LOCAL, FILE, path="123", oid="123", hash=b"123")
        state.update(LOCAL, FILE, path="456", oid="456", hash=b"456")
        state.update(LOCAL, FILE, path="789", oid="789", hash=b"789")
        state.lookup_oid(LOCAL, "456")[LOCAL].sync_path = "456"
        state.lookup_oid(LOCAL, "456").ignored = IgnoreReason.CONFLICT
        state.lookup_oid(LOCAL, "456")[LOCAL].changed = False

        state.storage_commit()

        args = MagicMock()

        args.state = tf.name
        args.json = arg_json
        args.discarded = arg_discard
        args.changed = arg_changed

        res = ""
        DebugCmd.run(args)
        res = capsys.readouterr().out

        assert "whatever" in res
        assert "123" in res

        if arg_json:
            log.info("json: %s", res)
            ret = json.loads(res)
            log.info("loaded: %s", ret)
            assert ret["whatever"]
            if arg_discard:
                if arg_changed:
                    assert len(ret["whatever"]) == 2
                else:
                    assert len(ret["whatever"]) == 3
            else:
                assert len(ret["whatever"]) == 2
    finally:
        storage.close()
