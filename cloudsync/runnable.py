"""
Generic 'runnable' abstract base class.

All cloudsync services inherit from this, instead of implementing their own
thread management.
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


class _BackoffError(Exception):
    pass


class Runnable(ABC):
    """
    Abstract base class for a runnable service.

    User needs to override and implement the "do" method.
    """
    # pylint: disable=multiple-statements
    min_backoff = 0.01                          ; """Min backoff time in seconds"""
    max_backoff = 1.0                           ; """Max backoff time in seconds"""
    mult_backoff = 2.0                          ; """Backoff multiplier"""
    in_backoff = 0.0                            ; """Current backoff seconds, 0.0 if not in a backoff state"""
    service_name = None                         ; """The name of this runnable service, defaults to the class name"""
    # pylint: enable=multiple-statements

    __thread = None
    __shutdown = False
    __interrupt: threading.Event = None
    __stopped = False
    __stopping = False
    __log: logging.Logger = None
    __clear_on_success: bool = True

    @property
    def stopped(self):
        """Set when you call stop(), causes the services to drop out."""
        return self.__stopped or self.__shutdown

    def interruptable_sleep(self, secs):
        """Call this instead of sleep, so the service can be interrupted"""
        if self.__interrupt and self.__interrupt.wait(secs):
            self.__interrupt.clear()

    def __increment_backoff(self):
        self.in_backoff = min(self.max_backoff, max(self.in_backoff * self.mult_backoff, self.min_backoff))

    def run(self, *, timeout=None, until=None, sleep=0.001):  # pylint: disable=too-many-branches
        """
        Calls do in a loop.

        Args:
            timeout: stop calling do after secs
            until: lambda returns bool
            sleep: seconds


        If an unhandled exception occurs, backoff sleep will occur.
        """
        if self.service_name is None:
            self.service_name = self.__class__.__name__

        self.__log = logging.getLogger(__name__ + "." + self.service_name)
        log.debug("running %s", self.service_name)

        # ordering of these two prevents race condition if you start/stop quickly
        # see `def started`
        self.__interrupt = threading.Event()
        self.__stopped = False

        try:
            for _ in time_helper(timeout):
                if self.__stopping or self.__shutdown:
                    break

                try:
                    self.__clear_on_success = True
                    self.do()
                    if self.__clear_on_success and self.in_backoff > 0:
                        self.in_backoff = 0
                        log.debug("%s: clear backoff", self.service_name)
                except _BackoffError:
                    self.__increment_backoff()
                    log.debug("%s: backing off %s", self.service_name, self.in_backoff)
                except Exception:
                    self.__increment_backoff()
                    log.exception("unhandled exception in %s", self.service_name)
                except BaseException:
                    self.__increment_backoff()
                    log.exception("very serious exception in %s", self.service_name)

                if self.__stopping or self.__shutdown or (until is not None and until()):
                    break

                if self.in_backoff > 0:
                    log.debug("%s: backoff sleep %s", self.service_name, self.in_backoff)
                    self.interruptable_sleep(self.in_backoff)
                else:
                    self.interruptable_sleep(sleep)
        finally:
            # clear started flag
            self.__stopping = False
            self.__stopped = True
            self.__interrupt = None

            if self.__shutdown:
                self.done()

            self.__thread = None
            log.debug("stopping %s", self.service_name)

    @property
    def started(self):
        """
        True if the service has been started and has not finished stopping
        """
        return self.__interrupt is not None

    @staticmethod
    def backoff():
        """
        Raises an exception, interrupting the durrent do() call, and sleeping for backoff seconds.
        """
        raise _BackoffError()

    def nothing_happened(self):
        """
        Sets a "nothing happened" flag.   This will cause backoff to remain the same, even on success.
        """
        self.__clear_on_success = False

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
        if self.service_name is None:
            self.service_name = self.__class__.__name__
        if self.__shutdown:
            raise RuntimeError("Service was stopped, create a new instance to run.")
        if self.__thread:
            raise RuntimeError("Service already started")
        self.__stopping = False
        self.__thread = threading.Thread(target=self.run, kwargs=kwargs, daemon=daemon, name=self.service_name)
        self.__thread.name = self.service_name
        self.__thread.start()

    @abstractmethod
    def do(self):
        """
        Override this to do something in a loop.
        """
        ...

    def stop(self, forever=True, wait=True):
        """
        Stop the service, allowing any do() to complete first.
        """
        self.__stopping = True
        self.wake()
        self.__shutdown = forever
        if self.__thread:
            if threading.current_thread() != self.__thread:
                if wait:
                    self.wait()
                self.__thread = None

    def done(self):
        """
        Cleanup code goes here.  This is called when a service is stopped.
        """

    def wait(self, timeout=None):
        """
        Wait for the service to stop.
        """
        if self.__thread and threading.current_thread() != self.__thread:
            self.__thread.join(timeout=timeout)
            if self.__thread and self.__thread.is_alive():
                raise TimeoutError()
            self.__thread = None
            return True
        else:
            return False
