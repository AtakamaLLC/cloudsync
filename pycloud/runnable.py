import time

from abc import ABC, abstractmethod

import threading
import logging
log = logging.getLogger(__name__)


def time_helper(timeout, sleep=None):
    forever = not timeout
    end = forever or time.monotonic() + timeout
    while forever or end >= time.monotonic():
        yield True
        if sleep is not None:
            time.sleep(sleep)


class Runnable(ABC):
    def run(self, *, timeout=None, until=None, sleep=0.1):
        self.stopped = False
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
        self.stopped = True

    def done(self):
        pass

def test_runnable():
    class Foo(Runnable):
        def __init__(self):
            self.cleaned=False
            self.done = 0

        def do(self):
            self.done += 1

        def done(self):
            self.cleaned = True

    foo = Foo()

    foo.run(timeout=0.02, sleep=0.001)

    assert foo.done

    foo.done = 0

    foo.run(until=lambda: foo.done == 1)

    assert foo.done == 1


    thread=threading.Thread(target=foo.run)
    thread.start()
    foo.stop()
    thread.join(timeout=1)

    assert foo.stopped == 1
