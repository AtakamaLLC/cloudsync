import threading
import logging

from typing import Optional, Tuple, List

from pystrict import strict

from .sync import SyncManager, SyncState, Storage
from .runnable import Runnable
from .event import EventManager
from .provider import Provider
from .log import TRACE

log = logging.getLogger(__name__)


@strict # pylint: disable=too-many-instance-attributes
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
        self.sleep = sleep

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
        log.info("initialized sync: %s", self.storage_label())

        self.sthread = None
        self.ethreads = (None, None)
        self.test_mgr_iter = None
        self.test_mgr_order: List[int] = []

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
        #     A tuple of (result, keep) or None, meaning there is no good resolution
        #     result is one of:
        #     - A "merged" file-like which should be used as the data to replace both f1/f2 with
        #     - One of f1 or f2,  which is selected as the correct version
        #     keep is true if we want to keep the old version of the file around as a .conflicted file, else False
        return None

    @property
    def change_count(self):
        return self.smgr.change_count

    def start(self, **kwargs):
        # override Runnable start/stop so that events can be processed in separate threads
        self.sthread = threading.Thread(target=self.smgr.run, kwargs={'sleep': 0.1, **kwargs}, daemon=True)
        self.ethreads = (
            threading.Thread(target=self.emgrs[0].run, kwargs={'sleep': self.sleep[0], **kwargs}, daemon=True),
            threading.Thread(target=self.emgrs[1].run, kwargs={'sleep': self.sleep[1], **kwargs}, daemon=True)
        )
        self.sthread.start()
        self.ethreads[0].start()
        self.ethreads[1].start()

    def stop(self, forever=True):
        log.info("stopping sync: %s", self.storage_label())
        self.smgr.stop(forever=forever)
        self.emgrs[0].stop(forever=forever)
        self.emgrs[1].stop(forever=forever)
        if self.sthread:
            self.sthread.join()
            self.ethreads[0].join()
            self.ethreads[1].join()
            self.sthread = None

    # for tests, make this manually runnable
    def do(self):
        # imports are in the body of this test-only function
        import random
        mgrs = [*self.emgrs, self.smgr]
        random.shuffle(mgrs)
        for m in mgrs:
            m.do()

        #  conceptually this should work, but our tests rely on changeset_len
        # instead we need to expose a stuff-to-do property in cs
        # if self.test_mgr_iter:
        #    try:
        #        r = next(self.test_mgr_iter)
        #    except StopIteration:
        #        r = random.randint(0, 2)
        # else:
        #    r = random.randint(0, 2)
        # self.test_mgr_order.append(r)
        # mgrs[r].do()

    def done(self):
        self.smgr.done()
        self.emgrs[0].done()
        self.emgrs[1].done()
