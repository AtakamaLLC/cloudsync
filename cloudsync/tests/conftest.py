import cloudsync

from .fixtures import *  # pylint: disable=unused-import, unused-wildcard-import, wildcard-import

cloudsync.logger.setLevel("TRACE")


def pytest_configure(config):
    config.addinivalue_line("markers", "manual")


def pytest_runtest_setup(item):
    if 'manual' in item.keywords and not item.config.getoption("--manual"):
        pytest.skip("need --manual option to run this test")


def pytest_addoption(parser):
    parser.addoption("--provider", action="append", default=[], help="provider(s) to run tests for")
    parser.addoption("--manual", action="store_true", default=False, help="run the manual tests")
