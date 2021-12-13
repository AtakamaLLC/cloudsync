import time
import threading
import logging
import pytest
from threading import Barrier

from cloudsync import Runnable
from cloudsync.tests.fixtures.util import RunUntilHelper

log = logging.getLogger(__name__)


def test_runnable():
    class TestRunTestRunnable(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            self.called += 1

        def done(self):
            self.cleaned = True

    testrun = TestRunTestRunnable()

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
    do_barrier_start = Barrier(2)
    do_barrier_end = Barrier(2)

    class TestRunTestTimeout(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            do_barrier_start.wait(10)  # tell the test we're started
            do_barrier_end.wait(10)  # hang here until the test is done testing
            self.called += 1

        def done(self):
            self.cleaned = True

    testrun = TestRunTestTimeout()
    testrun.start()
    do_barrier_start.wait(10)  # hang here until runnable gets into do()
    with pytest.raises(TimeoutError):
        testrun.wait(timeout=.01)

    # clean up
    do_barrier_end.wait(10)  # release the do loop from prison
    testrun.stop(wait=10)
    RunUntilHelper.wait_until(until=lambda: testrun.called, timeout=10)  # make sure do dropped out
    RunUntilHelper.wait_until(until=lambda: testrun.stopped, timeout=10)  # make sure the thread is done
    RunUntilHelper.wait_until(until=lambda: testrun.cleaned, timeout=10)  # make sure done was called


def test_start_exceptions():
    class TestRunTestStartExceptions(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            self.called += 1
            time.sleep(1)

        def done(self):
            self.cleaned = True

    testrun = TestRunTestStartExceptions()
    testrun.start()
    RunUntilHelper.wait_until(lambda: testrun.started)

    with pytest.raises(RuntimeError):
        testrun.start()

    testrun.stop(forever=False)
    testrun.start()
    testrun.stop(forever=True)
    with pytest.raises(RuntimeError):
        testrun.start()


def test_no_wait_stop():
    do_barrier_start = Barrier(2)
    do_barrier_end = Barrier(2)

    class TestRunTestNoWaitStop(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            do_barrier_start.wait(10)  # tell the test we're started
            do_barrier_end.wait(10)  # hang here until the test is done testing
            self.called += 1

        def done(self):
            self.cleaned = True

    testrun = TestRunTestNoWaitStop()
    testrun.start()
    do_barrier_start.wait(10)  # hang here until runnable gets into do()

    assert testrun.called == 0
    testrun.stop(wait=False)
    assert testrun.called == 0

    # the test framework chokes when the service stops after the test is complete and stop tries to log
    do_barrier_end.wait(10)  # release the do loop from prison
    RunUntilHelper.wait_until(until=lambda: testrun.called, timeout=10)  # make sure do dropped out
    RunUntilHelper.wait_until(until=lambda: testrun.stopped, timeout=10)  # make sure the thread is done
    RunUntilHelper.wait_until(until=lambda: testrun.cleaned, timeout=10)  # make sure done was called


def test_runnable_wake():
    class TestRunTestRunnableWake(Runnable):
        def __init__(self):
            self.cleaned = False
            self.called = 0

        def do(self):
            self.called += 1

        def done(self):
            self.cleaned = True

    testrun = TestRunTestRunnableWake()

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
