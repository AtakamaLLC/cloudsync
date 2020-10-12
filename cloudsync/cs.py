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
from .notification import NotificationManager, Notification, NotificationType, SourceEnum

log = logging.getLogger(__name__)


@strict  # pylint: disable=too-many-instance-attributes
class CloudSync(Runnable):
    """
    The main syncrhonization class used.
    """
    def __init__(self,
                 providers: Tuple[Provider, Provider],
                 roots: Optional[Tuple[str, str]] = None,
                 storage: Optional[Storage] = None,
                 sleep: Optional[Tuple[float, float]] = None,
                 root_oids: Optional[Tuple[str, str]] = None,
                 ):

        """
        Construct a new synchronizer between two providers.

        Args:
            providers: Two connected, authenticated providers.
            roots: The folder to synchronize
            storage: The back end storage mechanism for long-running sync information.
            sleep: The amount of time to sleep between event processing loops for each provider.
                   Defaults to the provider's default_sleep value.

        When run, will receive events from each provider, and use those events to trigger
            copying files from one provider to the other.

        Conflicts (changes made on both sides) are handled by renaming files, unless py::meth::`resolve_conflict`
            is overridden.

        The first time a sync starts up, it checks storage. If event cursors are invalid, or a walk has never
            been done, then the sync engine will trigger a walk of all files.

        File names are translated between both sides using the `translate` function, which can be overriden
            to deal with incompatible naming conventions, special character translation, etc.  By default,
            invalid names are not synced, and notifications about this are sent to py::method::`handle_notification`.
        """
        if not roots and self.translate == CloudSync.translate:     # pylint: disable=comparison-with-callable
            raise ValueError("Either override the translate() function, or pass in a pair of roots")

        self.providers = providers
        self.roots = roots

        if sleep is None:
            sleep = (providers[0].default_sleep, providers[1].default_sleep)
        self.sleep = sleep

        self.nmgr = NotificationManager(lambda n: self.handle_notification(n))  # pylint: disable=unnecessary-lambda

        # The tag for the SyncState will isolate the state of a pair of providers along with the sync roots

        # by using a lambda here, tests can inject functions into cs.prioritize, and they will get passed through
        state = SyncState(providers, storage, tag=self.storage_label(), shuffle=False,
                          prioritize=lambda *a: self.prioritize(*a))                              # pylint: disable=unnecessary-lambda

        smgr = SyncManager(state, providers, lambda *a, **kw: self.translate(*a, **kw),           # pylint: disable=unnecessary-lambda
                           self.resolve_conflict, self.nmgr, sleep=sleep)

        # for tests, make these accessible
        self.state = state
        self.smgr = smgr

        # the label for each event manager will isolate the cursor to the provider/login combo for that side
        event_root_paths: Tuple[Optional[str], Optional[str]] = roots or (None, None)
        event_root_oids: Tuple[Optional[str], Optional[str]] = root_oids or (None, None)

        self.emgrs: Tuple[EventManager, EventManager] = (
            EventManager(smgr.providers[0], state, 0, self.nmgr, root_path=event_root_paths[0],
                         reauth=lambda: self.authenticate(0), root_oid=event_root_oids[0]),
            EventManager(smgr.providers[1], state, 1, self.nmgr, root_path=event_root_paths[1],
                         reauth=lambda: self.authenticate(1), root_oid=event_root_oids[1])
        )
        log.info("initialized sync: %s, manager: %s", self.storage_label(), debug_sig(id(smgr)))

        self.sthread: threading.Thread = None
        self.ethreads: Tuple[threading.Thread, threading.Thread] = (None, None)
        self.test_mgr_iter = None
        self.test_mgr_order: List[int] = []

    def forget(self):
        """
        Forget and discard state information, and drop any events in the queue.  This will trigger a walk.
        """
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

    def walk(self, side=None, root=None, recursive=True):
        """Manually run a walk on a provider, causing a single-direction sync."""
        roots = self.roots or ('/', '/')
        if root is not None and side is None:
            # a root without a side makes no sense (which root ?)
            raise ValueError("If you specify a root, you need to specify which side")

        for index, provider in enumerate(self.providers):
            if side is not None and index != side:
                continue

            path = root
            if path is None:
                path = roots[index]

            # todo: this should not be called here, and instead, we should queue the walk itself
            for event in provider.walk(path, recursive=recursive):
                self.emgrs[index].queue(event, from_walk=True)

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
        """
        Number of relevant changes to be processed.
        """
        return self.smgr.change_count

    @property
    def busy(self):
        """
        True if there are any changes or events to be processed
        """
        return self.smgr.busy or self.emgrs[0].busy or self.emgrs[1].busy

    def start(self, *, daemon=True, **kwargs):
        """
        Starts the cloudsync service.
        """
        # Replaces :py:meth:`cloudsync.Runnable.start` so that events are processed asynchronously.
        self.sthread = threading.Thread(target=self.smgr.run, kwargs={'sleep': 0.1, **kwargs}, daemon=daemon)
        self.ethreads = (
            threading.Thread(target=self.emgrs[0].run, kwargs={'sleep': self.sleep[0], **kwargs}, daemon=daemon),
            threading.Thread(target=self.emgrs[1].run, kwargs={'sleep': self.sleep[1], **kwargs}, daemon=daemon)
        )
        self.sthread.start()
        self.ethreads[0].start()
        self.ethreads[1].start()
        log.debug('Starting the notification manager')
        self.nmgr.notify(Notification(SourceEnum.SYNC, NotificationType.STARTED, None))
        self.nmgr.start(**kwargs)

    def stop(self, forever=True, wait=True):
        """
        Stops the cloudsync service.

        Args:
            forever: If false is passed, then handles are left open for a future start.  Generally used for tests only.
        """
        log.info("stopping sync: %s", self.storage_label())
        self.smgr.stop(forever=forever, wait=wait)
        self.emgrs[0].stop(forever=forever, wait=wait)
        self.emgrs[1].stop(forever=forever, wait=wait)
        self.nmgr.stop(forever=forever, wait=wait)
        if self.sthread:
            self.sthread.join()
            self.ethreads[0].join()
            self.ethreads[1].join()
            self.nmgr.wait()  # TODO: wait() above instead of join()?
            self.sthread = None

    # for tests, make this manually runnable
    def do(self):
        """
        One loop of sync, used for *tests only*.

        This randomly chooses to process local events, remote events or local syncs.
        """
        # imports are in the body of this test-only function
        import random  # pylint: disable=import-outside-toplevel
        mgrs = [*self.emgrs, self.smgr]
        random.shuffle(mgrs)
        # conceptually, we should save the order of operations
        # self.test_mgr_order.append(order_of(mgrs))
        caught = None
        for m in mgrs:
            try:
                m.do()
            except Exception as e:
                log.error("exception in %s : %s", m.service_name, repr(e))
                caught = e
        if caught is not None:
            raise caught

    def done(self):
        """
        Called at shutdown, override if you need some shutdown code.
        """
        self.smgr.done()
        self.emgrs[0].done()
        self.emgrs[1].done()
        self.nmgr.done()

    def wait(self, timeout=None):
        """
        Wait for all threads.

        Will wait forever, unless stop() is called or timeout is specified.
        """
        for t in (self.sthread, self.ethreads[0], self.ethreads[1]):
            t.join(timeout=timeout)
            if t.is_alive():
                raise TimeoutError()

    def handle_notification(self, notification: Notification):
        """
        Override to receive notifications during sync processing.

        Args:
            notification: Information about errors, or other sync events.
        """
