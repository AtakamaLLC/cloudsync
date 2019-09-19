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
    shutdown = False
    wakeup = False
    thread = None

    def run(self, *, timeout=None, until=None, sleep=0.01):
        self.stopped = False
        self.wakeup = False
        endtime = sleep + time.monotonic()
        for _ in time_helper(timeout, sleep=.01):
            while time.monotonic() < endtime and not self.stopped and not self.wakeup:
                time.sleep(max(0, min(.01, endtime - time.monotonic())))
            self.wakeup = False
            if self.stopped:
                break
            try:
                self.do()
            except Exception:
                log.exception("unhandled exception in %s", self.__class__)
            if self.stopped or (until is not None and until()):
                break
            endtime = sleep + time.monotonic()

        if self.shutdown:
            self.done()

    def wake(self):
        self.wakeup = True

    def start(self, **kwargs):
        self.thread = threading.Thread(target=self.run, kwargs=kwargs, daemon=True)
        self.thread.start()

    @abstractmethod
    def do(self):
        ...

    def stop(self, forever=True):
        self.stopped = True
        self.shutdown = forever
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
