from abc import ABC, abstractmethod

from typing import NamedTuple, Optional

from re import split

# information returned 
class ProviderInfo(NamedTuple):             # todo, rename to FileInfo
    oid : str                               # file id       (better name: fid)
    hash : bytes                            # file hash     (better name: fhash)
    path : str                              # path

class Provider(ABC):
    sep: str = '/'                      # path delimiter
    case_sensitive = ...                # TODO: implement support for this
    allow_renames_over_existing = ...   # TODO: move this to the fixture, this is only needed for testing
    require_parent_folder = ...         # TODO: move this to the fixture, this is only needed for testing

    # TODO: this should be an abstractproperty ... not an ABC init which is incorrect
    def __init__(self):
        self.walked = False
        self.__connected = False

    @property
    @abstractmethod
    def connected(self):
        ...

    @abstractmethod
    def _api(self, *args, **kwargs):
        ...

    def connect(self, creds):
        # some providers don't need connections, so just don't implement this
        self.__connected = True

    @abstractmethod
    def events(self, timeout):
        ...

    @abstractmethod
    def walk(self):
        ...

    @abstractmethod
    def upload(self, oid, file_like, metadata):
        ...

    @abstractmethod
    def create(self, path, file_like, metadata) -> 'ProviderInfo':
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

    def normalize_path(self, path: str):
        norm_path = path.rstrip(self.sep)
        if self.sep in ["\\", "/"]:
            parts = split(r'[\\/]+', norm_path)
        else:
            parts = split(r'[%s]+' % self.sep, norm_path)
        norm_path = self.sep.join(parts)
        return norm_path

    def is_sub_path(self, folder, target, sep=None, anysep=False, strict=False):
        if sep is None:
            if anysep:
                sep = "/"
                folder = folder.replace("\\", "/")
                target = target.replace("\\", "/")
            else:
                sep = self.sep
        # Will return True for is-same-path in addition to target
        folder_full = str(folder)
        folder_full = folder_full.rstrip(sep)
        target_full = str(target)
        target_full = target_full.rstrip(sep)
        # .lower() instead of normcase because normcase will also mess with separators
        if not self.case_sensitive:
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

    def paths_match(self, patha, pathb):
        pass

    def dirname(self, path: str):
        norm_path = self.normalize_path(path)
        parts = split(r'[%s]+' % self.sep, norm_path)
        retval = self.sep + self.sep.join(parts[0:-1])
        return retval
