from cloudsync.utils import debug_args
import pytest
import logging

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
