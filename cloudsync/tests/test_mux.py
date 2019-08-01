import threading

from cloudsync.muxer import Muxer

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
            inner.count = 0
            for _ in m:
                inner.count += 1
        return inner

    m = [None] * threads
    c = [None] * threads
    t = [None] * threads

    for i in range(threads):
        m[i] = Muxer(gen)
        c[i] = counter(m[i])
        t[i] = threading.Thread(target=c[i])

    for i in range(threads):
        t[i].start()

    for i in range(threads):
        t[i].join()
        assert c[i].count == count

def test_later_mux():
    def gen():
        yield from range(4)

    m1 = Muxer(gen)

    assert next(m1) == 0

    m2 = Muxer(gen)

    assert len(list(m1)) == 3
    assert len(list(m2)) == 3

def test_restart_mux():
    def gen():
        yield from range(4)

    m1 = Muxer(gen, restart=True)
    m2 = Muxer(gen, restart=True)

    assert len(list(m1)) == 4
    assert len(list(m2)) == 8
    assert len(list(m1)) == 8
    assert len(list(m2)) == 8
