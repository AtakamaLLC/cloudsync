import pytest

from ..fixtures.mock_provider import MockProvider


@pytest.fixture
def cloudsync_provider():
    cls = MockProvider
    cls.event_timeout = 20
    cls.event_sleep = 2
    cls.creds = {}
    return cls
