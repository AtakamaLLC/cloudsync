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


class Runnable(ABC):
    stopped = False
    __shutdown = False
    wakeup = False
    thread = None
    min_backoff = 0.01
    max_backoff = 1
    mult_backoff = 2
    in_backoff = 0
    interrupt = None

    def interruptable_sleep(self, secs):
        self.interrupt.clear()
        self.interrupt.wait(secs)

    def run(self, *, timeout=None, until=None, sleep=0.01):
        self.interrupt = threading.Event()
        self.stopped = False
        for _ in time_helper(timeout, sleep=.01):
            self.interruptable_sleep(sleep)
            if self.stopped:
                break
            try:
                self.do()
                self.in_backoff = 0
            except Exception:
                log.exception("unhandled exception in %s", self.__class__)
            if self.stopped or (until is not None and until()):
                break

            if self.in_backoff:
                self.interruptable_sleep(self.in_backoff)

        if self.__shutdown:
            self.done()

    def backoff(self):
        self.in_backoff = max(self.in_backoff * self.mult_backoff, self.min_backoff)

    def wake(self):
        self.interrupt.set()

    def start(self, **kwargs):
        self.thread = threading.Thread(target=self.run, kwargs=kwargs, daemon=True)
        self.thread.start()

    @abstractmethod
    def do(self):
        ...

    def stop(self, forever=True):
        self.stopped = True
        self.interrupt.set()
        self.__shutdown = forever
        if self.thread:
            self.thread.join()
            self.thread = None
        elif forever:
            self.done()

    def done(self):
        # cleanup code goes here
        pass


def test_runnable():
    class TestRun(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            self.called += 1

        def done(self):
            self.cleaned = True

    testrun = TestRun()

    testrun.run(timeout=0.02, sleep=0.001)

    assert testrun.called

    testrun.called = 0

    testrun.run(until=lambda: testrun.called == 1)

    assert testrun.called == 1

    thread = threading.Thread(target=testrun.run)
    thread.start()
    testrun.stop()
    thread.join(timeout=1)

    assert testrun.stopped == 1
