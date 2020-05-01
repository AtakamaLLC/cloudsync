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
