import io
import sys
import logging
import json
import os, tempfile
from typing import IO

from unittest.mock import MagicMock

import pytest

from cloudsync.command.debug import do_debug

from cloudsync import SqliteStorage, SyncState, LOCAL, FILE, IgnoreReason

log = logging.getLogger()

# from https://gist.github.com/earonesty/a052ce176e99d5a659472d0dab6ea361
# windows compat

class TemporaryFile:
    def __init__(self, name, io, delete):
        self.name = name
        self.__io = io
        self.__delete = delete

    def __getattr__(self, k):
        return getattr(self.__io, k)

    def __del__(self):
        if self.__delete:
            try:
                os.unlink(self.name)
            except FileNotFoundError:
                pass

def NamedTemporaryFile(mode='w+b', bufsize=-1, suffix='', prefix='tmp', dir=None, delete=True):
    if not dir:
        dir = tempfile.gettempdir()
    name = os.path.join(dir, prefix + os.urandom(32).hex() + suffix)
    if mode is None:
        return TemporaryFile(name, None, delete)
    fh: IO = open(name, "w+b", bufsize)
    if mode != "w+b":
        fh.close()
        fh = open(name, mode)
    return TemporaryFile(name, fh, delete)


@pytest.mark.parametrize("arg_json", ["json", "nojson"])
@pytest.mark.parametrize("arg_discard", ["discard", "nodiscard"])
def test_debug_mode(arg_json, arg_discard):
    arg_json = arg_json[0:1] != "no"
    arg_discard = arg_discard[0:1] != "no"
    providers = (MagicMock(), MagicMock())

    tf = NamedTemporaryFile(mode=None)
    try:
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

        if arg_json:
            log.info("json: %s", res)
            ret = json.loads(res)
            log.info("loaded: %s", ret)
            assert ret["whatever"]
            if arg_discard:
                assert len(ret["whatever"]) == 2
            else:
                assert len(ret["whatever"]) == 1
    finally:
        storage.close()
