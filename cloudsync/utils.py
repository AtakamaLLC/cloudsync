import logging
import time
import functools

from hashlib import md5
from base64 import b64encode
from typing import Any, List, Dict, Callable, cast
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
def debug_sig(t: Any, size: int = 3) -> str:
    if not t:
        return "0"
    return b64encode(md5(str(t).encode()).digest()).decode()[0:size]


class disable_log_multiline:
    @staticmethod
    def _format(loggerclass, record):
        return loggerclass._fmt % record.__dict__       # pylint: disable=protected-access

    def __init__(self):
        self.patch_object = patch.object(PercentStyleMultiline, "format", new=disable_log_multiline._format)

    def __enter__(self):
        self.patch_object.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        self.patch_object.__exit__(*args, **kwargs)     # type: ignore


class memoize():
    """ Very simple memoize wrapper

    function decorator: cache lives globally
    method decorator: cache lives inside `obj_instance.__memoize_cache`
    """

    def __init__(self, func: Callable[..., Any] = None, expire_secs: float = 0, obj=None, cache: Dict[Any, Any] = None):
        self.func = func
        self.expire_secs = expire_secs
        self.cache = cache
        if cache is None:
            self.cache = {}
        if self.func is not None:
            functools.update_wrapper(self, func)
        self.obj = obj

    def __get__(self, obj, objtype=None):
        if obj is None:
            # does this ever happen?
            return self.func

        if type(self.cache) is str:
            # user specified name of a property that contains the cache dictionary
            cache = getattr(obj, cast(str, self.cache))
        else:
            # inject cache into the instance, so it doesn't live beyond the scope of the instance
            # without this, memoizing can cause serious unexpected memory leaks
            try:
                cache = obj.__memoize_cache          # pylint: disable=protected-access
            except AttributeError:
                try:
                    cache = obj.__memoize_cache = {}
                except Exception as e:
                    # some objects don't work with injection
                    log.warning("cannot inject cache: '%s', ensure object is a singleton, or pass a cache in!", e)
                    cache = self.cache

        return memoize(self.func, expire_secs=self.expire_secs, cache=cache, obj=obj)

    def __call__(self, *args, **kwargs):
        if self.func is None:
            # this was used as a function style decorator
            # there should be no kwargs
            assert not kwargs
            func = args[0]
            return memoize(func, expire_secs=self.expire_secs, cache=self.cache)

        if self.obj is not None:
            args = (self.obj, *args)

        key = (args, tuple(sorted(kwargs.items())))
        cur_time = time.monotonic()

        if key in self.cache:
            (cresult, ctime) = self.cache[key]
            if not self.expire_secs or cur_time < (ctime + self.expire_secs):
                return cresult

        result = self.func(*args, **kwargs)
        self.cache[key] = (result, cur_time)
        return result

    def clear(self, *args, **kwargs):
        if self.obj is not None:
            args = (self.obj, *args)
        key = (args, tuple(sorted(kwargs.items())))
        self.cache.pop(key, None)

    def get(self, *args, **kwargs):
        if self.obj is not None:
            args = (self.obj, *args)
        key = (args, tuple(sorted(kwargs.items())))
        if key in self.cache:
            return self.cache[key][0]
        return None

    def set(self, *args, _value, **kwargs):
        if self.obj is not None:
            args = (self.obj, *args)
        key = (args, tuple(sorted(kwargs.items())))
        self.cache[key] = (_value, time.monotonic())

