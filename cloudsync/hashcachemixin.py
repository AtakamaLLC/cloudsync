from threading import RLock
from typing import Dict

from .provider import Hash

__all__ = ["HashCacheMixin"]


# convenience class that can be mixed in for providers
class HashCacheMixin:
    def __init__(self, *ar, **kw):
        self.lock = RLock()
        self._oid_cache: Dict[str, Hash] = {}
        super().__init__(*ar, **kw)             # type: ignore

    # a provider that uses this mixin should leverage this function to speed up info_path and others too
    def hash_oid(self, oid) -> Hash:
        with self.lock:
            if oid in self._oid_cache:
                return self._oid_cache[oid]
        ret = super().hash_oid(oid)             # type: ignore
        with self.lock:
            self._oid_cache[oid] = ret
        return ret

    def events(self):
        for e in super().events():              # type: ignore
            with self.lock:
                if e.oid in self._oid_cache:
                    if self._oid_cache[e.oid] != e.hash:
                        self._oid_cache.pop(e.oid, None)
            yield e

    def upload(self, oid, file_like, metadata=None):
        ret = super().upload(oid, file_like, metadata)          # type: ignore
        if ret and ret.hash:
            with self.lock:
                self._oid_cache[oid] = ret.hash
        return ret

    def create(self, path, file_like, metadata=None):
        ret = super().create(path, file_like, metadata)         # type: ignore
        if ret and ret.hash:
            with self.lock:
                self._oid_cache[ret.oid] = ret.hash
        return ret

    def rename(self, oid, path):
        ret = super().rename(oid, path)                         # type: ignore
        if ret != oid:
            with self.lock:
                h = self._oid_cache.pop(oid, None)
                if h:
                    self._oid_cache[ret] = h
        return ret

    def info_oid(self, oid, **kws):
        ret = super().info_oid(oid, **kws)                             # type: ignore
        if ret:
            with self.lock:
                if ret.hash:
                    self._oid_cache[ret.oid] = ret.hash
                else:
                    self._oid_cache.pop(ret.oid, None)
        return ret

    def info_path(self, path):
        ret = super().info_path(path)                           # type: ignore
        if ret:
            with self.lock:
                if ret.hash:
                    self._oid_cache[ret.oid] = ret.hash
                else:
                    self._oid_cache.pop(ret.oid, None)
        return ret
