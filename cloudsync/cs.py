import threading

from .sync import SyncManager
from .runnable import Runnable
from .event import EventManager

class CloudSync(Runnable):
    def __init__(self, providers, translate, state):

        smgr = SyncManager(state, providers, translate)

        # for tests, make these accessible
        self.state = state
        self.providers = providers

        self.smgr = smgr
        self.emgrs = (
                EventManager(smgr.providers[0], state, 0),
                EventManager(smgr.providers[1], state, 1)
        )
        self.sthread = threading.Thread(target=smgr.run)
        self.ethreads = (
                threading.Thread(target=self.emgrs[0].run),
                threading.Thread(target=self.emgrs[1].run)
        )

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

