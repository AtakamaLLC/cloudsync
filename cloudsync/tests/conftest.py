from .fixtures import *  # pylint: disable=unused-import


def pytest_addoption(parser):
    parser.addoption(
        "--provider", action="append", default=[], help="provider(s) to run tests for"
    )
