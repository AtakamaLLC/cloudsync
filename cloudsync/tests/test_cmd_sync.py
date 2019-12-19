import os
import logging
import importlib
from tempfile import NamedTemporaryFile

from unittest.mock import MagicMock, patch

import pytest

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

    csync.do_sync(args)

    logs = caplog.record_tuples

    assert any("initialized" in t[2].lower() for t in logs)


@pytest.mark.parametrize("conf", ["with_conf", "no_conf"])
def test_sync_oauth(caplog, conf):
    args = MagicMock()

    args.src = "mock_oid_cs:/a"
    args.dest = "gdrive:/b"
    args.quiet = True           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit

    try:
        tf = NamedTemporaryFile(delete=False)
        tf.write(b'{"oauth":{"host":"localhost"}}')
        tf.flush()
        tf.close()

        if conf == "with_conf":
            args.config = tf.name
        else:
            args.config = "someconfigthatisnthere"

        log.info("start sync")
        with pytest.raises(CloudTokenError):
            csync.do_sync(args)
    finally:
        os.unlink(tf.name)

    logs = caplog.record_tuples

    assert any("connecting to google" in t[2].lower() for t in logs)


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
            csync.do_sync(args)
            dm.DaemonContext.assert_called_once()
    else:
        # daemon module is not available
        with patch.dict("sys.modules", {'daemon': None}):
            importlib.reload(csync)
            # import will fail here, which is ok
            with pytest.raises(NotImplementedError):
                csync.do_sync(args)
