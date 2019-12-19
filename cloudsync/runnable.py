"""
Generic 'runnable' abstract base class.   All cloudsync services inherit from this, instead of implementing their own.
"""

import time

from abc import ABC, abstractmethod

import threading
import logging
log = logging.getLogger(__name__)


def time_helper(timeout, sleep=None, multiply=1):
    """
    Simple generator that yields every `sleep` seconds, and stops after `timeout` seconds
    """
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
    """
    Abstract base class for a runnable service.

    User need only implement the "do" method.
    """
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
        """
        Calls do in a loop.

        Args:
            timeout: stop calling do after secs
            until: lambda returns bool
            sleep: seconds
        """
        if self.thread_name is None:
            self.thread_name = self.__class__.__name__

        log.debug("starting %s", self.thread_name)

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
                    log.debug("%s: clear backoff", self.thread_name)
            except BackoffError:
                self.__increment_backoff()
                log.debug("%s: backing off %s", self.thread_name, self.in_backoff)
            except Exception:
                self.__increment_backoff()
                log.exception("unhandled exception in %s", self.thread_name)
            except BaseException:
                self.__increment_backoff()
                log.exception("very serious exception in %s", self.thread_name)

            if self.stopped or (until is not None and until()):
                break

            if self.in_backoff > 0:
                log.debug("%s: backoff sleep %s", self.thread_name, self.in_backoff)
                self.interruptable_sleep(self.in_backoff)
            else:
                self.interruptable_sleep(sleep)

        # clear started flag
        self.__interrupt = None

        if self.__shutdown:
            self.done()

    @property
    def started(self):
        """
        True if currently running
        """
        return self.__interrupt is not None

    @staticmethod
    def backoff():
        """
        Interrupt the durrent do() call, and sleep for backoff seconds.
        """
        raise BackoffError()

    def wake(self):
        """
        Wake up, if do was sleeping, and do things right away.
        """
        if self.__interrupt is None:
            log.warning("not running, wake ignored")
            return
        self.__interrupt.set()

    def start(self, *, daemon=True, **kwargs):
        """
        Start a thread, kwargs are passed to run()
        """
        if self.thread_name is None:
            self.thread_name = self.__class__.__name__
        self.thread = threading.Thread(target=self.run, kwargs=kwargs, daemon=daemon, name=self.thread_name)
        self.thread.name = self.thread_name
        self.stopped = False
        self.thread.start()

    @abstractmethod
    def do(self):
        """
        Override this to do something in a loop.
        """
        ...

    def stop(self, forever=True):
        """
        Stop the service, allowing any do() to complete first.
        """
        self.stopped = True
        self.wake()
        self.__shutdown = forever
        if self.thread:
            self.wait()
            self.thread = None
        elif forever:
            self.done()

    def done(self):
        """
        Cleanup code goes here.  This is called when a service is stopped.
        """

    def wait(self, timeout=None):
        """
        Wait for the service to stop.
        """
        if self.thread:
            self.thread.join(timeout=timeout)
            if self.thread.is_alive():
                raise TimeoutError()
