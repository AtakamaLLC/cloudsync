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
    __interrupt: threading.Event = None
    thread_name = None

    def interruptable_sleep(self, secs):
        if self.__interrupt.wait(secs):
            self.__interrupt.clear()

    def __increment_backoff(self):
        self.in_backoff = min(self.max_backoff, max(self.in_backoff * self.mult_backoff, self.min_backoff))

    def run(self, *, timeout=None, until=None, sleep=0.001):
        service_name = self.thread_name or self.__class__
        log.debug("starting %s", service_name)

        # ordering of these two prevents race condition if you start/stop quickly
        # see `def started`
        self.stopped = False
        self.__interrupt = threading.Event()

        for _ in time_helper(timeout):
            if self.stopped:
                break

            try:
                self.do()
                if self.in_backoff > 0:
                    self.in_backoff = 0
                    log.debug("%s: clear backoff", service_name)
            except BackoffError:
                self.__increment_backoff()
                log.debug("%s: backing off %s", service_name, self.in_backoff)
            except Exception:
                self.__increment_backoff()
                log.exception("unhandled exception in %s", service_name)
            except BaseException:
                self.__increment_backoff()
                log.exception("very serious exception in %s", service_name)

            if self.stopped or (until is not None and until()):
                break

            if self.in_backoff > 0:
                log.debug("%s: backoff sleep %s", service_name, self.in_backoff)
                self.interruptable_sleep(self.in_backoff)
            else:
                self.interruptable_sleep(sleep)

        # clear started flag
        self.__interrupt = None

        if self.__shutdown:
            self.done()

    @property
    def started(self):
        return self.__interrupt is not None

    @staticmethod
    def backoff():
        raise BackoffError()

    def wake(self):
        if self.__interrupt is None:
            log.warning("not running, wake ignored")
            return
        self.__interrupt.set()

    def start(self, *, daemon=True, **kwargs):
        if self.thread_name is None:
            self.thread_name = self.__class__.__name__
        self.thread = threading.Thread(target=self.run, kwargs=kwargs, daemon=daemon, name=self.thread_name)
        self.thread.name = self.thread_name
        self.stopped = False
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

    def wait(self, timeout=None):
        if self.thread:
            self.thread.join(timeout=timeout)
            if self.thread.is_alive():
                raise TimeoutError()


