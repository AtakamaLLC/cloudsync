class Fake:
    name = "fake"


__cloudsync__ = Fake


import cloudsync.registry as registry


def test_registry_discover():
    assert registry.get_provider("fake") == Fake

