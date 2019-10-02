import os
import pytest
import logging

from cloudsync.utils import debug_args, TimeCache

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


def test_time_cache():
    func = lambda *a: (a, os.urandom(32))
    cached = TimeCache(func, 60)

    a = cached()
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

