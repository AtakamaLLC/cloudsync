import time
import threading
import logging
import pytest

from cloudsync.long_poll import LongPollManager

log = logging.getLogger(__name__)


def wait_for(f, timeout):
    t = threading.Thread(target=f, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        raise TimeoutError()


class lpfix:
    """Longpoll fixture"""
    def __init__(self, *, q=None):
        self.orig_q = q or [1, 2, 3]
        self.q = self.orig_q.copy()
        self.has_stuff = True
        self.ready = threading.Event()
        self.raised = 0
        self.lpcalls = 0

    def sp(self):
        log.debug("queue: %s", self.q)
        for i in self.q:
            yield i
        self.q = []

    def lp(self, timeout):
        self.lpcalls += 1
        self.ready.wait(timeout=timeout)
        if isinstance(self.has_stuff, Exception):
            self.raised += 1
            raise self.has_stuff
        return self.has_stuff


@pytest.mark.parametrize("uses_cursor", [0, 1])
def test_lpsimple(uses_cursor):
    """Basic lp test"""
    lp = lpfix()

    man = LongPollManager(lp.sp, lp.lp, uses_cursor=uses_cursor)

    man.start()
    lp.ready.set()
    assert list(man()) == lp.orig_q
    assert lp.q == []
    man.stop()


@pytest.mark.parametrize("uses_cursor", [0, 1])
def test_lpwait(uses_cursor):
    """Wait forever cause False, exception is try it"""
    lp = lpfix()

    man = LongPollManager(lp.sp, lp.lp, uses_cursor=uses_cursor)
    man.long_poll_timeout = 0.01

    # this prevents it from ever returning
    lp.has_stuff = False

    man.start()

    if uses_cursor:
        # this should time-out, because it never has stuff
        with pytest.raises(TimeoutError):
            wait_for(lambda: log.debug("to: %s", list(man())), timeout=0.1)
    else:
        # we dont trust the return value from longpoll without cursors
        assert list(man()) == lp.orig_q
    man.stop()


def test_cursor_mode():
    """Wait forever cause False, exception is try it"""
    uses_cursor = 1

    lp = lpfix()

    if uses_cursor:
        # short polling is very very slow
        lp.sp = lambda: time.sleep(10)  # type: ignore

    man = LongPollManager(lp.sp, lp.lp, uses_cursor=uses_cursor)
    man.long_poll_timeout = 1

    lp.has_stuff = True

    man.start()

    if uses_cursor:
        log.info("shouldn't long poll more than once, because short pollint takes too long")
        with pytest.raises(TimeoutError):
            wait_for(lambda: log.debug("to: %s", list(man())), timeout=0.1)
        assert lp.lpcalls == 1
    man.stop()


@pytest.mark.parametrize("uses_cursor", [0, 1])
def test_lpex(uses_cursor):
    """Wait forever cause False, exception is try it"""
    lp = lpfix()

    man = LongPollManager(lp.sp, lp.lp, uses_cursor=uses_cursor)
    man.long_poll_timeout = 0.01
    man.start()

    lp.has_stuff = Exception("exceptions cause lp to be conservative")  # type: ignore

    assert list(man()) == lp.orig_q
    assert lp.raised > 0

    with pytest.raises(TimeoutError):
        # give the runnable system time to process the exception
        man.wait(timeout=0.1)

    # lpman is backing off
    assert man.in_backoff > 0

    man.stop()
