import time
import threading
import logging
import pytest

from cloudsync import Runnable

log = logging.getLogger(__name__)


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

    with pytest.raises(TimeoutError):
        testrun.run(timeout=0.02, sleep=0.001)

    assert testrun.called

    testrun.called = 0

    testrun.run(until=lambda: testrun.called == 1)

    assert testrun.called == 1

    thread = threading.Thread(target=testrun.run, kwargs={"timeout": 10})
    thread.start()
    while not testrun.started:
        time.sleep(0.1)
    testrun.stop(forever=False)
    thread.join(timeout=1)
    assert testrun.stopped
    assert not thread.is_alive()

    assert testrun.stopped == 1

    testrun.called = 0
    testrun.start(until=lambda: testrun.called > 0)
    testrun.wait(timeout=2)


def test_timeout():
    class TestRun(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            self.called += 1
            time.sleep(10)

        def done(self):
            self.cleaned = True

    testrun = TestRun()
    testrun.start()
    while not testrun.started:
        time.sleep(.01)
    with pytest.raises(TimeoutError):
        testrun.wait(timeout=.01)

def test_start_exceptions():
    class TestRun(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            self.called += 1
            time.sleep(10)

        def done(self):
            self.cleaned = True

    testrun = TestRun()
    testrun.start()
    while not testrun.started:
        time.sleep(.01)

    with pytest.raises(RuntimeError):
        testrun.start()

    testrun.stop(forever=False)
    testrun.start()
    testrun.stop(forever=True)
    with pytest.raises(RuntimeError):
        testrun.start()

def test_no_wait_stop():
    class TestRun(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            time.sleep(10)
            self.called += 1

        def done(self):
            self.cleaned = True

    testrun = TestRun()
    testrun.start()
    while not testrun.started:
        time.sleep(.01)

    assert testrun.called == 0
    testrun.stop(wait=False)
    assert testrun.called == 0

def test_runnable_wake():
    class TestRun(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            self.called += 1

        def done(self):
            self.cleaned = True

    testrun = TestRun()

    # noop
    log.info("noop")
    testrun.wake()

    # this will sleep for a long time, doing nothing
    thread = threading.Thread(target=testrun.run, kwargs={"sleep": 10, "timeout": 10})
    thread.start()

    # called once at start, then sleepz
    while testrun.called == 0:
        time.sleep(0.1)
    assert testrun.called == 1

    while not testrun.started:
        time.sleep(0.1)

    # now sleeping for 10 secs, doing nothing
    assert testrun.called == 1

    log.info("wake")
    # wake it up right away
    testrun.wake()
    while testrun.called == 1:
        time.sleep(0.1)
    assert testrun.called == 2

    testrun.stop()
    thread.join(timeout=2)
    assert not thread.is_alive()
