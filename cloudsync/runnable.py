import time

from abc import ABC, abstractmethod

import threading
import logging
log = logging.getLogger(__name__)


def time_helper(timeout, sleep=None, multiply=1):
    forever = not timeout
    end = forever or time.monotonic() + timeout
    while forever or end >= time.monotonic():
        yield True
        if sleep is not None:
            time.sleep(sleep)
            sleep = sleep * multiply
    raise TimeoutError()


class BackoffError(Exception):
    pass


class Runnable(ABC):
    stopped = False
    __shutdown = False
    wakeup = False
    thread = None
    min_backoff = 0.01
    max_backoff = 1.0
    mult_backoff = 2.0
    in_backoff = 0.0
    interrupt: threading.Event = None
    thread_name = None

    def __interruptable_sleep(self, secs):
        if self.interrupt.wait(secs):
            self.interrupt.clear()

    def __increment_backoff(self):
        log.debug("increment 1 %s %s", self.in_backoff, self.max_backoff)
        self.in_backoff = min(self.max_backoff, max(self.in_backoff * self.mult_backoff, self.min_backoff))
        log.debug("increment 2 %s %s", self.in_backoff, self.max_backoff)

    def run(self, *, timeout=None, until=None, sleep=0.001):
        self.interrupt = threading.Event()
        self.stopped = False
        for _ in time_helper(timeout):
            self.__interruptable_sleep(sleep)
            if self.stopped:
                break

            try:
                self.do()
                if self.in_backoff > 0:
                    self.in_backoff = 0
                    log.debug("%s: clear backoff", self.thread_name or self.__class__)
            except BackoffError:
                self.__increment_backoff()
                log.debug("%s: backing off %s", self.thread_name or self.__class__, self.in_backoff)
            except Exception:
                self.__increment_backoff()
                log.exception("unhandled exception in %s", self.thread_name or self.__class__)

            if self.stopped or (until is not None and until()):
                break

            if self.in_backoff > 0:
                log.debug("%s: backoff sleep %s", self.thread_name or self.__class__, self.in_backoff)
                self.__interruptable_sleep(self.in_backoff)

            if self.stopped:
                break

        if self.__shutdown:
            self.done()

    @staticmethod
    def backoff():
        raise BackoffError()

    def wake(self):
        if not self.interrupt:
            log.warning("not running, wake ignored")
            return
        self.interrupt.set()

    def start(self, *, daemon=True, **kwargs):
        if self.thread_name is None:
            self.thread_name = self.__class__.__name__
        self.thread = threading.Thread(target=self.run, kwargs=kwargs, daemon=daemon, name=self.thread_name)
        self.thread.name = self.thread_name
        self.thread.start()

    @abstractmethod
    def do(self):
        ...

    def stop(self, forever=True):
        self.stopped = True
        self.wake()
        self.__shutdown = forever
        if self.thread:
            self.wait()
            self.thread = None
        elif forever:
            self.done()

    def done(self):
        # cleanup code goes here
        pass

    def wait(self):
        if self.thread:
            self.thread.join()

