import threading
import logging

from typing import Optional, Tuple, List, IO, Any

from pystrict import strict

from .sync import SyncManager, SyncState, Storage
from .runnable import Runnable
from .event import EventManager
from .provider import Provider
from .log import TRACE
from .utils import debug_sig

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

        # by using a lambda here, tests can inject functions into cs.prioritize, and they will get passed through 
        state = SyncState(providers, storage, tag=self.storage_label(), shuffle=False,
                prioritize=lambda *a: self.prioritize(*a))                              # pylint: disable=unnecessary-lambda

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
            EventManager(smgr.providers[0], state, 0, _roots[0], reauth=lambda: self.authenticate(0)),
            EventManager(smgr.providers[1], state, 1, _roots[1], reauth=lambda: self.authenticate(1))
        )
        log.info("initialized sync: %s, manager: %s", self.storage_label(), debug_sig(id(smgr)))

        self.sthread = None
        self.ethreads = (None, None)
        self.test_mgr_iter = None
        self.test_mgr_order: List[int] = []

    def forget(self):
        self.state.forget()
        self.emgrs[0].forget()
        self.emgrs[1].forget()

    @property
    def aging(self) -> float:
        """float: The number of seconds to wait before syncing a file.   

        Reduces storage provider traffic at the expense of increased conflict risk.  

        Default is based on the max(provider.default_sleep) value
        """
        return self.smgr.aging

    @aging.setter
    def aging(self, secs: float):
        self.smgr.aging = secs

    def storage_label(self):
        """
        Returns:
            str: a unique label representing this paired, translated sync

        Override this if if you are re-using storage and are using a rootless translate.
        """

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

    def authenticate(self, side: int):     # pylint: disable=unused-argument, no-self-use
        """Override this method to change (re)authentication

        Default is to call provider[side].authenticate()

        Args:
            side: either 0 (LOCAL) or 1 (REMOTE)

        """
        self.providers[side].connect(self.providers[side].authenticate())

    def prioritize(self, side: int, path: str):     # pylint: disable=unused-argument, no-self-use
        """Override this method to change the sync priority

        Default priority is 0
        Negative values happen first
        Positive values happen later

        Args:
            side: either 0 (LOCAL) or 1 (REMOTE)
            path: a path value in the (side) provider

        """
        return 0

    def translate(self, side: int, path: str):
        """Override this method to translate between local and remote paths

        By default uses `self.roots` to strip the path provided, and 
        join the result to the root of the other side.

        If `self.roots` is None, this function must be overridden.

        Example:
            translate(REMOTE, "/home/full/local/path.txt") -> "/cloud/path.txt"

        Args:
            side: either 0 (LOCAL) or 1 (REMOTE)
            path: a path valid in the (1-side) provider

        Returns:
             The path, valid for the provider[side], or None to mean "don't sync"
        """
        if not self.roots:
            raise ValueError("Override translate function or provide root paths")

        relative = self.providers[1-side].is_subpath(self.roots[1-side], path)
        if not relative:
            log.log(TRACE, "%s is not subpath of %s", path, self.roots[1-side])
            return None
        return self.providers[side].join(self.roots[side], relative)

    def resolve_conflict(self, f1: IO, f2: IO) -> Tuple[Any, bool]:     # pylint: disable=no-self-use, unused-argument
        """Override this method to handle conflict resolution of files

        Note:
         - f1 and f2 are file-likes that will block on read, and can possibly pull data from the network, internet, etc
         - f1 and f2 also support the .path property to get a relative path to the file
         - f1 and f2 also support the .side property

        Returns:
             A tuple of (result, keep) or None, meaning there is no good resolution
             result is one of:
             - A "merged" file-like which should be used as the data to replace both f1/f2 with
             - One of f1 or f2,  which is selected as the correct version
             keep is true if we want to keep the old version of the file around as a .conflicted file, else False
        """
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
        import random  # pylint: disable=import-outside-toplevel
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
