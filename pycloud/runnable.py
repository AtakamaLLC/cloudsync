import time

from abc import ABC, abstractmethod

import logging
log = logging.getLogger(__name__)


def time_helper(secs, sleep=None):
    forever = not secs
    end = forever or time.monotonic() + secs
    while forever or end >= time.monotonic():
        yield True
        if sleep is not None:
            time.sleep(sleep)


class Runnable(ABC):
    def __init__(self):
        self.stopped = False  # TODO implement stopping

    def run(self, *, timeout=None, until=None, sleep=0.1):
        for _ in time_helper(timeout, sleep=sleep):
            if until is not None and until():
                break

            try:
                self.do()
            except Exception:
                log.exception("unhandled exception in %s", self.__class__)

    @abstractmethod
    def do(self):
        ...

    def stop(self):
        self.stopped = True


def test_runnable():
    done = 0

    class Foo(Runnable):
        def do(self):
            nonlocal done
            done += 1
            pass

    foo = Foo()

    foo.run(timeout=0.02, sleep=0.001)

    assert done

    done = 0

    foo.run(until=lambda: done == 1)

    assert done == 1
