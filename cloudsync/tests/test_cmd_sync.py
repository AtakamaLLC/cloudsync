import os
import logging
import importlib
from tempfile import NamedTemporaryFile

from unittest.mock import MagicMock, patch

import pytest

from cloudsync import get_provider
from cloudsync.exceptions import CloudTokenError
import cloudsync.command.sync as csync

log = logging.getLogger(__name__)


def test_sync_basic(caplog):
    args = MagicMock()

    args.src = "mock_oid_cs:/a"
    args.dest = "mock_path_cs:/b"
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit

    csync.SyncCmd.run(args)

    logs = caplog.record_tuples

    assert any("initialized" in t[2].lower() for t in logs)


@pytest.mark.parametrize("conf", ["with_conf", "no_conf"])
@pytest.mark.parametrize("quiet", [True, False])
def test_sync_oauth(caplog, conf, quiet):
    args = MagicMock()

    args.src = "mock_oid_cs:/a"
    args.dest = "gdrive:/b"
    args.quiet = quiet           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit

    try:
        tf = NamedTemporaryFile(delete=False)
        tf.write(b'{"oauth":{"host":"localhost"}}')
        tf.flush()
        tf.close()

        tf2 = NamedTemporaryFile(delete=False)
        tf2.write(b'{"mock_oid_cs":{"fake":"creds"}}')
        tf2.flush()
        tf2.close()

        args.creds = tf2.name

        if conf == "with_conf":
            args.config = tf.name
        else:
            args.config = "someconfigthatisnthere"

        log.info("start sync")
        with pytest.raises(CloudTokenError):
            with patch.object(get_provider("gdrive"), "authenticate") as mock_auth:
                try:
                    csync.SyncCmd.run(args)
                except CloudTokenError:
                    if args.quiet:
                        mock_auth.assert_not_called()
                    else:
                        mock_auth.assert_called_once()
                    raise
    finally:
        os.unlink(tf.name)
        os.unlink(tf2.name)

    logs = caplog.record_tuples

    assert any("connect gdrive" in t[2].lower() for t in logs)


@pytest.mark.parametrize("daemon", ["with_daemon", "no_daemon"])
def test_sync_daemon(daemon):
    args = MagicMock()

    args.src = "mock_oid_cs:/a"
    args.dest = "mock_path_cs:/b"
    args.daemon = True         # don't keep running after i quit

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
