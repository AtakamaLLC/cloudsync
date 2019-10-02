import logging
import time
import functools

from hashlib import md5
from base64 import b64encode
from typing import Any, Union, List, Dict, Callable
from unittest.mock import patch
from _pytest.logging import PercentStyleMultiline

log = logging.getLogger(__name__)


MAX_DEBUG_STR = 64


def _debug_arg(val: Any):
    ret: Any = val
    if isinstance(val, dict):
        r: Dict[Any, Any] = {}
        for k, v in val.items():
            r[k] = _debug_arg(v)
        ret = r
    elif isinstance(val, str):
        if len(val) > 64:
            ret = val[0:61] + "..."
    elif isinstance(val, bytes):
        if len(val) > 64:
            ret = val[0:61] + b"..."
    else:
        try:
            rlist: List[Any] = []
            for v in iter(val):
                rlist.append(_debug_arg(v))
            ret = rlist
        except TypeError:
            pass
    return ret


# prevents very long arguments from getting logged
def debug_args(*stuff: Any):
    if log.isEnabledFor(logging.DEBUG):
        r = _debug_arg(stuff)
        if len(r) == 1:
            r = r[0]
        return r
    return "N/A"


# useful for converting oids and pointer nubmers into digestible nonces
def debug_sig(t: Any, size: int = 3) -> Union[str, int]:
    if not t:
        return 0
    return b64encode(md5(str(t).encode()).digest()).decode()[0:size]


class disable_log_multiline:
    @staticmethod
    def _format(loggerclass, record):
        return loggerclass._fmt % record.__dict__  # pylint: disable=protected-access

    def __init__(self):
        self.patch_object = patch.object(PercentStyleMultiline, "format", new=disable_log_multiline._format)

    def __enter__(self):
        self.patch_object.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        self.patch_object.__exit__(*args, **kwargs)


class memoize():
    """ very simple memoize wrapper
    when used as a decorator... the memo lives globally
    for instance methods, use x.method = memoize(x.method)
    """

    def __init__(self, func: Callable[..., Any] = None, expire_secs: float = 0):
        self.func = func
        self.expire_secs = expire_secs
        self.cached_results: Dict[Any, Any] = {}
        self.last_time: float = 0
        self._inst = None
        if self.func is not None:
            functools.update_wrapper(self, func)

    def __get__(self, obj, objtype=None):
        # called when memoize is on a class
        self._inst = obj
        if obj is None:
            return self.func
        return self

    def __call__(self, *args, **kwargs):
        if self.func is None:
            # this allows function style decorators
            func = args[0]
            return memoize(func, *args[1:], *kwargs)

        if self._inst:
            # this was used as a method wrapper
            args = (self._inst, *args)

        key = (args, tuple(sorted(kwargs.items())))
        cur_time = time.monotonic()

        if key in self.cached_results:
            (cresult, ctime) = self.cached_results[key]
            if not self.expire_secs or cur_time < (ctime + self.expire_secs):
                return cresult

        result = self.func(*args, **kwargs)
        self.cached_results[key] = (result, cur_time)
        return result

    def clear(self, *args, **kwargs):
        key = (args, tuple(sorted(kwargs.items())))
        self.cached_results.pop(key, None)

    def get(self, *args, **kwargs):
        key = (args, tuple(sorted(kwargs.items())))
        if key in self.cached_results:
            return self.cached_results[key][0]
        return None

    def set(self, *args, _value, **kwargs):
        key = (args, tuple(sorted(kwargs.items())))
        self.cached_results[key] = (_value, time.monotonic())

