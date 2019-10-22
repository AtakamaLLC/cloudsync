import io
import sys
import logging
import pytest
import json

from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock

from cloudsync.command.debug import do_debug

from cloudsync import SqliteStorage, SyncState, LOCAL, FILE, IgnoreReason

log = logging.getLogger()


@pytest.mark.parametrize("arg_json", ["json", "nojson"])
@pytest.mark.parametrize("arg_discard", ["discard", "nodiscard"])
def test_debug_mode(arg_json, arg_discard):
    arg_json = arg_json[0:1] != "no"
    arg_discard = arg_discard[0:1] != "no"
    providers = (MagicMock(), MagicMock())
    with NamedTemporaryFile() as tf:
        storage = SqliteStorage(tf.name)
        state = SyncState(providers, storage, tag="whatever")
        state.update(LOCAL, FILE, path="123", oid="123", hash=b"123")
        state.update(LOCAL, FILE, path="456", oid="456", hash=b"456")
        state.lookup_oid(LOCAL, "456")[LOCAL].sync_path = "456"
        state.lookup_oid(LOCAL, "456").ignored = IgnoreReason.CONFLICT

        state.storage_commit()

        args = MagicMock()

        args.state = tf.name
        args.json = arg_json
        args.discarded = arg_discard

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        cap_out = io.StringIO()
        sys.stdout = cap_out

        res = ""
        try:
            do_debug(args)
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            res = cap_out.getvalue()

        assert "whatever"  in res
        assert "123" in res

        if json:
            log.info("json: %s", res)
            ret = json.loads(res)
            log.info("loaded: %s", ret)
            assert ret["whatever"]
            if arg_discard:
                assert len(ret["whatever"]) == 2
            else:
                assert len(ret["whatever"]) == 1


