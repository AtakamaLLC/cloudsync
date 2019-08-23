import threading
from typing import Optional, Tuple

from .sync import SyncManager, SyncState, Storage
from .runnable import Runnable
from .event import EventManager
from .provider import Provider


class CloudSync(Runnable):
    def __init__(self,
                 providers: Tuple[Provider, Provider],
                 roots: Tuple[str, str] = None,
                 storage: Optional[Storage] = None,
                 sleep: Optional[int] = 15,
                 ):

        self.providers = providers
        self.roots = roots

        # The tag for the SyncState will isolate the state of a pair of providers along with the sync roots
        state = SyncState(storage, tag=self.storage_label())
        smgr = SyncManager(state, providers, self.translate, sleep=sleep)

        # for tests, make these accessible
        self.state = state
        self.smgr = smgr

        # the label for each event manager will isolate the cursor to the provider/login combo for that side
        self.emgrs: Tuple[EventManager, EventManager] = (
            EventManager(smgr.providers[0], state, 0, sleep=sleep),
            EventManager(smgr.providers[1], state, 1, sleep=sleep)
        )
        self.sthread = threading.Thread(target=smgr.run)
        self.ethreads = (
            threading.Thread(target=self.emgrs[0].run),
            threading.Thread(target=self.emgrs[1].run)
        )

    def storage_label(self):
        assert self.providers[0].connection_id is not None
        assert self.providers[1].connection_id is not None
        return f"{self.providers[0].name}:{self.providers[0].connection_id}:{self.roots[0]}."\
               f"{self.providers[1].name}:{self.providers[1].connection_id}:{self.roots[1]}"

    def walk(self):
        if not self.roots:
            raise ValueError("walk requires provider path roots")

        for index, provider in enumerate(self.providers):
            for event in provider.walk(self.roots[index]):
                self.emgrs[index].process_event(event)

    def translate(self, index, path):
        relative = self.providers[1-index].is_subpath(self.roots[1-index], path)
        if not relative:
            return None
        return self.providers[index].join(self.roots[index], relative)

    def start(self):
        self.sthread.start()
        self.ethreads[0].start()
        self.ethreads[1].start()

    def stop(self):
        self.smgr.stop()
        self.emgrs[0].stop()
        self.emgrs[1].stop()

    # for tests, make this manually runnable
    def do(self):
        self.smgr.do()
        self.emgrs[0].do()
        self.emgrs[1].do()

    def done(self):
        self.smgr.done()
        self.emgrs[0].done()
        self.emgrs[1].done()
