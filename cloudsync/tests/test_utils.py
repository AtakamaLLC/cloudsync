from cloudsync.utils import debug_args


def test_debug_args():
    res = debug_args([1,2,3])
    assert res == [1,2,3]
    res = debug_args([1,2,3], {1:2}, True)
    assert res == [[1,2,3],{1:2}, True]
    res = debug_args({"k":b'0'*100})
    assert res == {"k":b'0'*61 + b'...'}
