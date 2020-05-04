from unittest.mock import MagicMock, patch

import pytest

from cloudsync.tests.fixtures import MockProvider
import cloudsync.command.list as csync


@pytest.mark.parametrize("long", [True, False])
def test_list_basic(caplog, long):
    args = MagicMock()

    args.prov = "mock_oid_cs:/"
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.long = long

    with patch.object(MockProvider, "listdir_path") as mock:
        csync.ListCmd.run(args)
        mock.assert_called_once()

    logs = caplog.record_tuples

    assert any("connect mock" in t[2].lower() for t in logs)

def test_list_err(caplog, tmpdir):
    args = MagicMock()

    args.prov = "gdrive:/"
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.long = False
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
def test_list_fs(capsys, long, tmpdir):
    args = MagicMock()

    # make one long to test size formatting code path
    (tmpdir / "foo").write("yo" * 2048)
    (tmpdir / "bar").write("yo")

    args.prov = "filesystem:%s" % tmpdir
    args.quiet = False           # log less, don't prompt for auth, get tokens from files or other commands
    args.verbose = True         # log a lot (overrides quiet)
    args.daemon = False         # don't keep running after i quit
    args.long = long

    csync.ListCmd.run(args)

    out = capsys.readouterr().out

    assert "foo" in out
    assert "bar" in out

    # todo: fs prov shows size, mtime reliably!
    # if long:
    #    assert "2K" in out
