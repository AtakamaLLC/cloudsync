from abc import ABC, abstractmethod

import re

from cloudsync.types import OInfo

class Provider(ABC):                    # pylint: disable=too-many-public-methods
    sep: str = '/'                      # path delimiter
    alt_sep: str = '\\'                 # alternate path delimiter
    case_sensitive = ...                # TODO: implement support for this
    require_parent_folder = ...         # TODO: move this to the fixture, this is only needed for testing
    auto_vivify_parent_folders = ...    # TODO: move this to the fixture, this is only needed for testing

    # TODO: this should be an abstractproperty ... not an ABC init which is incorrect
    def __init__(self, sync_root):
        self.sync_root = sync_root
        self.walked = False
        self.__connected = False

    @property
    @abstractmethod
    def connected(self):
        ...


    @abstractmethod
    def _api(self, *args, **kwargs):
        ...

    def connect(self, creds):           # pylint: disable=unused-argument
        # some providers don't need connections, so just don't implement this
        self.__connected = True

    @abstractmethod
    def events(self):
        ...

    @abstractmethod
    def walk(self, since=None):
        ...

    @abstractmethod
    def upload(self, oid, file_like, metadata):
        ...

    @abstractmethod
    def create(self, path, file_like, metadata) -> 'OInfo':
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

    @abstractmethod
    def listdir(self, oid) -> list:
        ...

#    @abstractmethod
#    def hash_oid(self, oid) -> Any:
#        ...

    @abstractmethod
    def info_path(self, path) -> OInfo:
        ...

    @abstractmethod
    def info_oid(self, oid) -> OInfo:
        ...

    def join(self, paths):
        res = ""
        for path in paths:
            if path is None or path == self.sep:
                continue
            res = res + self.sep + path.strip(self.sep)
        return res or self.sep

    def split(self, path):
        # todo cache regex
        index = path.rfind(self.sep)
        if index == -1 and self.alt_sep:
            index = path.rfind(self.alt_sep)
        if index == -1:
            return (path, "")
        if index == 0:
            return (self.sep, path[index+1:])
        return (path[:index], path[index+1:])

    def normalize_path(self, path: str):
        norm_path = path.rstrip(self.sep)
        if self.sep in ["\\", "/"]:
            parts = re.split(r'[\\/]+', norm_path)
        else:
            parts = re.split(r'[%s]+' % self.sep, norm_path)
        norm_path = self.sep.join(parts)
        return norm_path

    def is_subpath(self, folder, target, sep=None, anysep=False, strict=False):
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
        relative = self.is_subpath(path, from_dir)
        if relative:
            return to_dir + relative
        raise ValueError("replace_path used without subpath")

    def paths_match(self, patha, pathb):
        pass

    def dirname(self, path: str):
        norm_path = self.normalize_path(path)
        parts = re.split(r'[%s]+' % self.sep, norm_path)
        retval = self.sep + self.sep.join(parts[0:-1])
        return retval
