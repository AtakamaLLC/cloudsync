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


class Runnable(ABC):
    def run(self, *, timeout=None, until=None, sleep=0.01):
        self.stopped = False                      # pylint: disable=attribute-defined-outside-init

        for _ in time_helper(timeout, sleep=sleep):
            if self.stopped or (until is not None and until()):
                break
            try:
                self.do()
            except Exception:
                log.exception("unhandled exception in %s", self.__class__)

        if self.stopped:
            self.done()

    @abstractmethod
    def do(self):
        ...

    def stop(self):
        self.stopped = True                                                     # pylint: disable=attribute-defined-outside-init

    def done(self):
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
