from hashlib import md5
from base64 import b64encode
from typing import Any, Union
# useful for converting oids and pointer nubmers into digestible nonces


def debug_sig(t: Any, size: int = 3) -> Union[str, int]:
    if not t:
        return 0
    return b64encode(md5(str(t).encode()).digest()).decode()[0:size]
