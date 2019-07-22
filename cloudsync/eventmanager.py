from .runnable import Runnable

class EventManager(Runnable):
    def __init__(self, provider, state, side):
        self.provider = provider
        self.state = state
        self.side = side

    def do(self):
        for event in self.provider.events():
            self.state.update(self.side, event.otype, event.oid, path=event.path, hash=event.hash, exists=event.exists)
