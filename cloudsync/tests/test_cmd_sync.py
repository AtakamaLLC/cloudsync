import os
import logging
from tempfile import NamedTemporaryFile

from unittest.mock import MagicMock, patch

import pytest

from cloudsync.exceptions import CloudTokenError
from cloudsync.command.sync import do_sync

log = logging.getLogger(__name__)


def test_sync_basic(caplog):
    args = MagicMock()

    args.src = "mock_oid_cs:/a"
    args.dest = "mock_path_cs:/b"
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit

    do_sync(args)

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

    with NamedTemporaryFile() as tf:
        tf.write(b'{"oauth":{"host":"localhost"}}')

        tf.flush()

        if conf == "with_conf":
            args.config = tf.name
        else:
            args.config = "someconfigthatisnthere"

        log.info("start sync")
        with pytest.raises(CloudTokenError):
            do_sync(args)

    logs = caplog.record_tuples

    assert any("connecting to google" in t[2].lower() for t in logs)


def test_sync_daemon():
    args = MagicMock()

    args.src = "mock_oid_cs:/a"
    args.dest = "mock_path_cs:/b"
    args.daemon = True         # don't keep running after i quit

    with patch("daemon.DaemonContext") as dc:
        # if you don't patch, then this will fork... not what you want
        do_sync(args)

    dc.assert_called_once()
