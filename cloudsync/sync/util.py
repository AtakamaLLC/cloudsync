from hashlib import md5
from base64 import b64encode

# useful for converting oids and pointer nubmers into digestible nonces


def debug_sig(t, size=3):
    if not t:
        return 0
    return b64encode(md5(str(t).encode()).digest()).decode()[0:size]
