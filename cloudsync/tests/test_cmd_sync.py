# pylint: disable=protected-access, missing-docstring

import os
import sys
import logging
import importlib
from tempfile import NamedTemporaryFile

from unittest.mock import MagicMock, patch

import pytest

from cloudsync import get_provider
from cloudsync.exceptions import CloudTokenError
import cloudsync.command.sync as csync

log = logging.getLogger(__name__)

def test_cmd_sync_basic(caplog, tmpdir):
    args = MagicMock()

    args.src = "mock_oid_cs:/a"
    args.dest = "mock_path_cs:/b"
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.statedb = str(tmpdir / "storage")
    args.creds = "whatevs"

    csync.SyncCmd.run(args)
    logs = caplog.record_tuples
    assert any("initialized" in t[2].lower() for t in logs)


@pytest.mark.parametrize("conf", ["with_conf", "no_conf"])
@pytest.mark.parametrize("creds", ["with_creds", "no_creds"])
@pytest.mark.parametrize("quiet", [True, False])
def test_cmd_sync_oauth(caplog, conf, creds, quiet, tmpdir):
    args = MagicMock()

    args.src = "mock_oid_cs:/a"
    args.dest = "gdrive:/b"
    args.quiet = quiet           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.statedb = str(tmpdir / "storage")

    try:
        tf = NamedTemporaryFile(delete=False)
        tf.write(b'{"oauth":{"host":"localhost"}}')
        tf.flush()
        tf.close()

        tf2 = NamedTemporaryFile(delete=False)
        tf2.write(b'{"mock_oid_cs":{"fake":"creds"}}')
        tf2.flush()
        tf2.close()

        err: type = CloudTokenError

        if sys.platform == "linux":
            badname = "/not-allowed"
            plat_err = PermissionError
        else:
            badname = "x:/bad"
            plat_err = FileNotFoundError

        args.creds = tf2.name if creds == "with_creds" else badname

        if conf == "with_conf":
            args.config = tf.name
        else:
            args.config = "someconfigthatisnthere"

        log.info("start sync")

        if creds != "with_creds" and not args.quiet:
            err = plat_err

        with pytest.raises(err):
            called = 0

            def authen(self):
                nonlocal called
                self._oauth_config.creds_changed({"k":"v"})
                called += 1
                return {"k":"v"}

            with patch.object(get_provider("gdrive"), "authenticate", authen):
                try:
                    csync.SyncCmd.run(args)
                except CloudTokenError:
                    if args.quiet:
                        assert called == 0
                    else:
                        assert called == 1
                    raise
    finally:
        os.unlink(tf.name)
        os.unlink(tf2.name)

    logs = caplog.record_tuples

    if err == CloudTokenError:
        assert any("connect gdrive" in t[2].lower() for t in logs)

@pytest.mark.parametrize("daemon", ["with_daemon", "no_daemon"])
def test_cmd_sync_daemon(daemon, tmpdir):
    args = MagicMock()

    args.src = "mock_oid_cs:/a"
    args.dest = "mock_path_cs:/b"
    args.daemon = True         # don't keep running after i quit
    args.statedb = str(tmpdir / "storage")

    if daemon == "with_daemon":
        # daemon module is available - forcibly
        dm = MagicMock()
        with patch.dict("sys.modules", {'daemon': dm}):
            importlib.reload(csync)
            csync.SyncCmd.run(args)
            dm.DaemonContext.assert_called_once()
    else:
        # daemon module is not available
        with patch.dict("sys.modules", {'daemon': None}):
            importlib.reload(csync)
            # import will fail here, which is ok
            with pytest.raises(NotImplementedError):
                csync.SyncCmd.run(args)
