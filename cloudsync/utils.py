import logging
from hashlib import md5
from base64 import b64encode
from typing import Any, Union

log = logging.getLogger(__name__)


MAX_DEBUG_STR = 64

def _debug_arg(v):
    if isinstance(v, dict):
        r = {}
        for k, v in v.items():
            r[k] = _debug_arg(v)
        return r

    if isinstance(v, str):
        if len(v) > 64:
            return v[0:61] + "..."
        return v

    if isinstance(v, bytes):
        if len(v) > 64:
            return v[0:61] + b"..."
        return v

    try:
        r = []
        for v in iter(v):
            r.append(_debug_arg(v))
        return r
    except TypeError:
        return v

# prevents very long arguments from getting logged
def debug_args(*stuff: Any):
    if log.isEnabledFor(logging.DEBUG):
        r = _debug_arg(stuff)
        if len(r) == 1:
            r = r[0]
        return r

# useful for converting oids and pointer nubmers into digestible nonces
def debug_sig(t: Any, size: int = 3) -> Union[str, int]:
    if not t:
        return 0
    return b64encode(md5(str(t).encode()).digest()).decode()[0:size]

