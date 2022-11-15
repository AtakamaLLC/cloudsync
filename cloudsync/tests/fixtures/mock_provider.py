import pytest

from cloudsync.registry import register_provider
from cloudsync.providers.mock import MockProvider


def mock_provider_instance(*args, **kws):
    prov = MockProvider(*args, **kws)
    prov.connect({"key": "val"})
    return prov


@pytest.fixture(name="mock_provider", params=[(False, True), (True, True)], ids=["mock_oid_cs", "mock_path_cs"])
def mock_provider_fixture(request):
    return mock_provider_instance(*request.param)


@pytest.fixture(params=[(False, True), (True, True)], ids=["mock_oid_cs", "mock_path_cs"])
def mock_provider_generator(request):
    return lambda oid_is_path=None, case_sensitive=None: \
        mock_provider_instance(
            request.param[0] if oid_is_path is None else oid_is_path,
            request.param[1] if case_sensitive is None else case_sensitive)


def mock_provider_tuple_instance(local, remote):
    return (
        mock_provider_instance(oid_is_path=local[0], case_sensitive=local[1], filter_events=local[2]),
        mock_provider_instance(oid_is_path=remote[0], case_sensitive=remote[1], filter_events=remote[2])
    )


# parameterization:
# - (oid-cs-unfiltered, oid-cs-unfiltered)
# - (path-cs-unfiltered, oid-cs-filtered)
@pytest.fixture(params=[((False, True, False), (False, True, False)), ((True, True, False), (False, True, True))],
                ids=["mock_oid_cs_unfiltered", "mock_path_cs_filtered"])
def mock_provider_tuple(request):
    return mock_provider_tuple_instance(request.param[0], request.param[1])


# parameterization:
# - (oid-ci-unfiltered, oid-ci-unfiltered)
# - (path-ci-unfiltered, oid-ci-filtered)
@pytest.fixture(params=[((False, False, False), (False, False, False)), ((True, False, False), (False, False, True))],
                ids=["mock_oid_cs_unfiltered", "mock_path_cs_filtered"])
def mock_provider_tuple_ci(request):
    return mock_provider_tuple_instance(request.param[0], request.param[1])


@pytest.fixture
def mock_provider_creator():
    return mock_provider_instance


# one of two default providers for test_provider.py tests
class MockPathCs(MockProvider):
    name = "mock_path_cs"

    def __init__(self):
        super().__init__(oid_is_path=True, case_sensitive=True)


class MockPathCi(MockProvider):
    name = "mock_path_ci"

    def __init__(self):
        super().__init__(oid_is_path=True, case_sensitive=False)


class MockOidCs(MockProvider):
    name = "mock_oid_cs"

    def __init__(self):
        super().__init__(oid_is_path=False, case_sensitive=True)


# one of two default providers for test_provider.py tests
class MockOidCi(MockProvider):
    name = "mock_oid_ci"

    def __init__(self):
        super().__init__(oid_is_path=False, case_sensitive=False, use_ns=False)


class MockOidCiNs(MockProvider):
    name = "mock_oid_ci_ns"

    def __init__(self):
        super().__init__(oid_is_path=False, case_sensitive=False, use_ns=True)


register_provider(MockPathCs)
register_provider(MockPathCi)
register_provider(MockOidCs)
register_provider(MockOidCi)
register_provider(MockOidCiNs)
