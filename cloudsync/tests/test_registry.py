import logging
log = logging.getLogger(__name__)


class Fake:
    def __init__(self, *args, **kwargs):
        if kwargs.get('test'):
            self.test = kwargs['test']
        else:
            self.test = None
            log.error("Arguments to Fake provider init: args=%s kwargs=%s", args, kwargs)

    name = "fake"


__cloudsync__ = Fake


import cloudsync.registry as registry


def test_registry_discover():
    assert registry.get_provider("fake") == Fake
    provider = registry.create_provider("fake", test='testvalue')
    assert isinstance(provider, Fake)
    assert provider.test == 'testvalue'

