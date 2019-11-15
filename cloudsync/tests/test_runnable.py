import time
import threading
import pytest

from cloudsync import Runnable


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

    thread = threading.Thread(target=testrun.run)
    thread.start()
    testrun.stop()
    thread.join(timeout=1)

    assert testrun.stopped == 1


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
    testrun.wake()

    # this will sleep for a long time, doing nothing
    thread = threading.Thread(target=testrun.run, kwargs={"sleep": 10})
    thread.start()
    time.sleep(0.1)
    assert not testrun.called
    # that wakes it up
    testrun.wake()
    while not testrun.called:
        time.sleep(0.1)
    assert testrun.called
    testrun.stop()
    thread.join(timeout=1)
