# pylint: disable=missing-docstring

import logging
from unittest.mock import MagicMock, patch

import pytest

from cloudsync.tests.fixtures import MockProvider
from cloudsync import CloudNamespaceError
import cloudsync.command.list as csync

log = logging.getLogger(__name__)

@pytest.mark.parametrize("long", [True, False])
def test_list_basic(caplog, long):
    args = MagicMock()

    logging.getLogger().setLevel(logging.DEBUG)
    args.prov = "mock_oid_cs:/"
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.long = long
    args.namespaces = False

    with patch.object(MockProvider, "listdir_path") as mock:
        csync.ListCmd.run(args)
        mock.assert_called_once()

    logs = caplog.record_tuples

    assert any("connect mock" in t[2].lower() for t in logs)

def test_list_ns(caplog, capsys):
    args = MagicMock()

    args.prov = "mock_oid_ci_ns@ns1:/"
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.long = False
    args.namespaces = True

    csync.ListCmd.run(args)

    logs = caplog.record_tuples
    out = capsys.readouterr().out

    log.debug("out %s", out)

    assert any("connect mock" in t[2].lower() for t in logs)

    # mock prov lists ns1, ns2 as namespaces

    assert "ns1" in out
    assert "ns2" in out


def test_list_badns():
    args = MagicMock()

    args.prov = "mock_oid_ci_ns@namespace:/"
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.long = False
    args.namespaces = True

    with pytest.raises(CloudNamespaceError):
        csync.ListCmd.run(args)

def test_list_err(tmpdir):
    args = MagicMock()

    args.prov = "gdrive:/"
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.long = False
    args.namespaces = False

    badj = tmpdir / "bad"
    with open(badj, "w") as f:
        f.write("bad stuff")
    args.config = str(badj)
    with pytest.raises(ValueError):
        csync.ListCmd.run(args)
    args.config = "file not found"
    args.creds = str(badj)
    with pytest.raises(ValueError):
        csync.ListCmd.run(args)
    args.creds = "file not found"
    args.prov = "-dfjfhj::fdsf:/"
    with pytest.raises(ValueError):
        csync.ListCmd.run(args)


@pytest.mark.parametrize("long", [True, False])
@pytest.mark.parametrize("fsname", ["file", "filesystem"])
def test_list_fs(capsys, long, fsname, tmpdir):
    args = MagicMock()

    # make one long to test size formatting code path
    (tmpdir / "foo").write("yo" * 2048)
    (tmpdir / "bar").write("yo")

    args.prov = "%s:%s" % (fsname, tmpdir)
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.long = long
    args.namespaces = False

    csync.ListCmd.run(args)

    out = capsys.readouterr().out

    assert "foo" in out
    assert "bar" in out

    # todo: fs prov shows size, mtime reliably!
    # if long:
    #    assert "2K" in out
