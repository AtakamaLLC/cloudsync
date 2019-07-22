from .runnable import Runnable


class EventManager(Runnable):
    def __init__(self, provider):
        super().__init__()
        self.provider = provider
        self.timeout = 1

    def do(self):  # One iteration of the loop
        for e in self.provider.events(timeout=self.timeout):
            if e is None:
                continue
            # update the state by calling update with the info from the event
