import os
import pytest
import logging

from cloudsync.utils import debug_args, memoize

log = logging.getLogger(__name__)


def test_debug_args():
    res = debug_args([1,2,3])
    assert res == [1,2,3]
    res = debug_args([1,2,3], {1:2}, True)
    assert res == [[1,2,3],{1:2}, True]
    res = debug_args({"k":b'0'*100})
    assert res == {"k":b'0'*61 + b'...'}


@pytest.mark.manual
def test_multiline():
    from cloudsync.utils import disable_log_multiline
    log.error("indented line1\n<--- weird pytest indentation")
    with disable_log_multiline():
        log.error("not indented line1\n<--- right up against the edge of the terminal")


def test_memoize1():
    func = lambda *a: (a, os.urandom(32))
    cached = memoize(func, 60)

    a = cached()
    assert cached.get() == a
    b = cached()
    # same vals
    assert a == b

    # clear test
    cached.clear()
    b = cached()
    assert a != b

    # with param test
    p1 = cached(32)

    assert p1[0] == (32,)
    assert p1 != b and p1 != a
    p2 = cached(32)
    p3 = cached(33)

    assert p1 == p2
    assert p3[0] == (33,)

    # clears z only
    cached.clear(32)
    p4 = cached(33)

    assert p3 == p4

    # zero param is still ok
    a = cached()
    assert a == b

    b = cached.get()
    assert a == b

    cached.clear()
    assert cached.get() is None

    cached.set(3, b=4, _value=44)
    assert cached.get(3, b=4) == 44
    assert cached(3, b=4) == 44

def test_memoize2():
    @memoize
    def fun(a):
        return (a, os.urandom(32))

    x = fun(1)
    y = fun(1)
    assert x == y
    z = fun(2)
    assert z != x

    @memoize(expire_secs=3)
    def fun2(a):
        return (a, os.urandom(32))

    x = fun2(1)
    y = fun2(1)
    assert x == y
    z = fun2(2)
    assert z != x


def test_memoize3():
    class Cls:
        @memoize
        def fun(self, a):
            return (a, os.urandom(32))

        @memoize
        def fun2(self):
            return os.urandom(32)

    # different self's
    x = Cls().fun(1)
    y = Cls().fun(1)
    assert x != y

    c = Cls()
    x = c.fun(1)
    assert c.fun.get(1) == x
    assert c.fun.get(1)
    y = c.fun(1)
    assert x == y
    z = c.fun(2)
    assert z != x

    log.debug("no args test")
    m = c.fun2()
    assert m
    assert c.fun2.get() == m

