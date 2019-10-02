import logging
import time

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


class TimeCache():
    def __init__(self, cache_func: Callable[..., Any], cache_secs: float):
        self.cache_func = cache_func
        self.cache_secs = cache_secs
        self.cached_results: Dict[Any, Any] = {}
        self.last_time: float = 0

    def __call__(self, *args, **kwargs):
        key = (args, tuple(sorted(kwargs.items())))
        cur_time = time.monotonic()

        if key in self.cached_results:
            (cresult, ctime) = self.cached_results[key]
            if cur_time < (ctime + self.cache_secs):
                return cresult

        result = self.cache_func(*args, **kwargs)
        self.cached_results[key] = (result, cur_time)
        return result

    def clear(self, *args, **kwargs):
        key = (args, tuple(sorted(kwargs.items())))
        self.cached_results.pop(key, None)

