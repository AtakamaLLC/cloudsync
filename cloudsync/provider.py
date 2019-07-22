from abc import ABC, abstractmethod
from collections import namedtuple
from cloudsync.event import Event

ProviderInfo = namedtuple('ProviderInfo', 'oid hash path')


class ProviderEvent(ABC):
    pass


class Provider(ABC):
    def __init__(self, case_sensitive=True, allow_renames_over_existing=True, sep="/"):
        self._sep = sep  # path delimiter
        self._case_sensitive = case_sensitive  # TODO: implement support for this
        self._allow_renames_over_existing = allow_renames_over_existing
        self._events = []
        self._event_cursor = 0
        self.walked = False

    @abstractmethod
    def _api(self, *args, **kwargs):
        ...

    @abstractmethod
    def events(self, timeout):
        ...

    @abstractmethod
    def walk(self):
        ...

    @abstractmethod
    def upload(self, oid, file_like):
        ...

    @abstractmethod
    def create(self, path, file_like) -> 'ProviderInfo':
        ...

    @abstractmethod
    def download(self, oid, file_like):
        ...

    @abstractmethod
    def rename(self, oid, path):
        ...

    @abstractmethod
    def mkdir(self, path) -> str:
        ...

    @abstractmethod
    def delete(self, oid):
        ...

    @abstractmethod
    def exists_oid(self, oid):
        ...

    @abstractmethod
    def exists_path(self, path) -> bool:
        ...

    @staticmethod
    @abstractmethod
    def hash_data(file_like):
        ...

    @abstractmethod
    def remote_hash(self, oid):
        ...

    @abstractmethod
    def info_path(self, path) -> ProviderInfo:
        ...

    @abstractmethod
    def info_oid(self, oid) -> ProviderInfo:
        ...

    def is_sub_path(self, folder, target, sep=None, anysep=False, strict=False):
        if sep is None:
            if anysep:
                sep = "/"
                folder = folder.replace("\\", "/")
                target = target.replace("\\", "/")
            else:
                sep = self._sep
        # Will return True for is-same-path in addition to target
        folder_full = str(folder)
        folder_full = folder_full.rstrip(sep)
        target_full = str(target)
        target_full = target_full.rstrip(sep)
        # .lower() instead of normcase because normcase will also mess with separators
        if not self._case_sensitive:
            folder_full = folder_full.lower()
            target_full = target_full.lower()

        # target is same as folder, or target is a subpath (ensuring separator is there for base)
        if folder_full == target_full:
            return False if strict else sep
        elif len(target_full) > len(folder_full) and \
                target_full[len(folder_full)] == sep:
            if target_full.startswith(folder_full):
                return target_full.replace(folder_full, "", 1)
            else:
                return False
        return False

    def replace_path(self, path, from_dir, to_dir):
        relative = self.is_sub_path(path, from_dir)
        if relative:
            return to_dir + relative
        raise ValueError("replace_path used without subpath")

