import threading

from cloudsync.muxer import Muxer

from typing import Callable, List

def test_simple_mux():
    def gen():
        yield from range(4)

    m1 = Muxer(gen)
    m2 = Muxer(gen)

    assert len(list(m1)) == 4
    assert len(list(m2)) == 4


def test_thready_mux():
    threads = 10

    count = 1000

    def gen():
        yield from range(count)

    def counter(m):
        def inner():
            inner.count = 0         # type: ignore
            for _ in m:
                inner.count += 1    # type: ignore
        return inner

    m: List[Muxer] = [None] * threads
    c: List[Callable] = [None] * threads
    t: List[threading.Thread] = [None] * threads

    for i in range(threads):
        m[i] = Muxer(gen)
        c[i] = counter(m[i])
        t[i] = threading.Thread(target=c[i], daemon=True)

    for i in range(threads):
        t[i].start()

    for i in range(threads):
        t[i].join()
        assert c[i].count == count  # type: ignore


def test_later_mux():
    def gen():
        yield from range(4)

    m1 = Muxer(gen)

    assert next(m1) == 0

    m2 = Muxer(gen)

    assert len(m1.listeners) == 2

    assert len(list(m1)) == 3
    assert len(list(m2)) == 3


def test_restart_mux():
    def gen():
        yield from range(4)

    m1 = Muxer(gen, restart=True)
    m2 = Muxer(gen, restart=True)

    assert len(m1.listeners) == 2

    assert len(list(m1)) == 4
    assert len(list(m2)) == 8
    assert len(list(m1)) == 8
    assert len(list(m2)) == 8


def test_del():
    def gen():
        yield from range(4)

    m1 = Muxer(gen)

    _ = next(m1)

    m2 = Muxer(gen)
    lm2 = list(m2)
    assert len(m2.listeners) == 2
    assert len(lm2) == 3

    m2.__del__()
    assert len(m1.listeners) == 1

    _ = list(m1)

    assert gen in Muxer.already

    m1.__del__()

    assert len(m1.listeners) == 0

    assert gen not in Muxer.already
