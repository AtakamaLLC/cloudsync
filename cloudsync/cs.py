import threading
import logging

from typing import Optional, Tuple

from pystrict import strict

from .sync import SyncManager, SyncState, Storage
from .runnable import Runnable
from .event import EventManager
from .provider import Provider
from .log import TRACE

log = logging.getLogger(__name__)


@strict
class CloudSync(Runnable):
    def __init__(self,
                 providers: Tuple[Provider, Provider],
                 roots: Optional[Tuple[str, str]] = None,
                 storage: Optional[Storage] = None,
                 sleep: Optional[Tuple[float, float]] = None,
                 ):

        if not roots and self.translate == CloudSync.translate:     # pylint: disable=comparison-with-callable
            raise ValueError("Either override the translate() function, or pass in a pair of roots")

        self.providers = providers
        self.roots = roots

        if sleep is None:
            sleep = (providers[0].default_sleep, providers[1].default_sleep)

        # The tag for the SyncState will isolate the state of a pair of providers along with the sync roots
        state = SyncState(providers, storage, tag=self.storage_label(), shuffle=False)
        smgr = SyncManager(state, providers, self.translate, self.resolve_conflict, sleep=sleep)

        # for tests, make these accessible
        self.state = state
        self.smgr = smgr

        # the label for each event manager will isolate the cursor to the provider/login combo for that side
        _roots: Tuple[Optional[str], Optional[str]]
        if not roots:
            _roots = (None, None)
        else:
            _roots = roots

        self.emgrs: Tuple[EventManager, EventManager] = (
            EventManager(smgr.providers[0], state, 0, _roots[0]),
            EventManager(smgr.providers[1], state, 1, _roots[1])
        )
        self.sthread = threading.Thread(target=smgr.run, kwargs={'sleep': 0.1})

        self.ethreads = (
            threading.Thread(target=self.emgrs[0].run, kwargs={'sleep': sleep[0]}),
            threading.Thread(target=self.emgrs[1].run, kwargs={'sleep': sleep[1]})
        )

        log.info("initialized sync: %s", self.storage_label())

    @property
    def aging(self):
        return self.smgr.aging

    @aging.setter
    def aging(self, val):
        self.smgr.aging = val

    def storage_label(self):
        # if you're using a pure translate, and not roots, you don't have to override the storage label
        # just don't resuse storage for the same pair of providers

        roots = self.roots or ('?', '?')
        assert self.providers[0].connection_id is not None
        assert self.providers[1].connection_id is not None
        return f"{self.providers[0].name}:{self.providers[0].connection_id}:{roots[0]}."\
               f"{self.providers[1].name}:{self.providers[1].connection_id}:{roots[1]}"

    def walk(self):
        roots = self.roots or ('/', '/')
        for index, provider in enumerate(self.providers):
            for event in provider.walk(roots[index]):
                self.emgrs[index].process_event(event)

    def translate(self, index, path):
        if not self.roots:
            raise ValueError("Override translate function or provide root paths")

        relative = self.providers[1-index].is_subpath(self.roots[1-index], path)
        if not relative:
            log.log(TRACE, "%s is not subpath of %s", path, self.roots[1-index])
            return None
        return self.providers[index].join(self.roots[index], relative)

    @staticmethod
    def resolve_conflict(_f1, _f2):
        # Input:
        #     - f1 and f2 are file-likes that will block on read, and can possibly pull data from the network, internet, etc
        #     - f1 and f2 also support the .path property to get a relative path to the file
        #     - f1 and f2 also support the .side property
        #
        # Return Values:
        #
        #     - A "merged" file-like which should be used as the data to replace both f1/f2 with
        #     - One of f1 or f2,  which is selected as the correct version
        #     - "None", meaning there is no good resolution
        return None

    @property
    def change_count(self):
        return self.smgr.change_count

    def start(self):
        self.sthread.start()
        self.ethreads[0].start()
        self.ethreads[1].start()

    def stop(self):
        log.info("stopping sync: %s", self.storage_label())
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
