import logging
from hashlib import md5
from base64 import b64encode
from typing import Any, Union, List, Dict
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
