from abc import ABC, abstractmethod
import re
from typing import Generator

from cloudsync.types import OInfo, DIRECTORY, DirInfo
from cloudsync.exceptions import CloudFileNotFoundError, CloudFileExistsError


class Provider(ABC):                    # pylint: disable=too-many-public-methods
    sep: str = '/'                      # path delimiter
    alt_sep: str = '\\'                 # alternate path delimiter
    oid_is_path = False
    case_sensitive = True

    @abstractmethod
    def _api(self, *args, **kwargs):
        ...

    def connect(self, creds):           # pylint: disable=unused-argument
        # some providers don't need connections, so just don't implement this
        pass

    @abstractmethod
    def events(self):
        ...

    @abstractmethod
    def walk(self, path, since=None):
        ...

    @abstractmethod
    def upload(self, oid, file_like, metadata=None) -> 'OInfo':
        ...

    @abstractmethod
    def create(self, path, file_like, metadata=None) -> 'OInfo':
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
    def listdir(self, oid) -> Generator[DirInfo, None, None]:
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

# CONVENIENCE
    def download_path(self, path, io):
        info = self.info_path(path)
        if not info or not info.oid:
            raise CloudFileNotFoundError()
        self.download(info.oid, io)

# HELPER
    @classmethod
    def join(cls, *paths):
        res = ""
        for path in paths:
            if path is None or path == cls.sep:
                continue
            if isinstance(path, str):
                res = res + cls.sep + path.strip(cls.sep)
                continue
            for sub_path in path:
                if sub_path is None or sub_path == cls.sep:
                    continue
                res = res + cls.sep + sub_path.strip(cls.sep)
        return res or cls.sep

    def split(self, path):
        # todo cache regex
        index = path.rfind(self.sep)
        if index == -1 and self.alt_sep:
            index = path.rfind(self.alt_sep)
        if index == -1:
            return path, ""
        if index == 0:
            return self.sep, path[index+1:]
        return path[:index], path[index+1:]

    def normalize_path(self, path: str):
        norm_path = path.rstrip(self.sep)
        if self.sep in ["\\", "/"]:
            parts = re.split(r'[\\/]+', norm_path)
        else:
            parts = re.split(r'[%s]+' % self.sep, norm_path)
        norm_path = self.join(*parts)
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
        relative = self.is_subpath(from_dir, path)
        if relative:
            return to_dir + relative
        raise ValueError("replace_path used without subpath")

    def paths_match(self, patha, pathb):
        pass

    def dirname(self, path: str):
        norm_path = self.normalize_path(path).lstrip(self.sep)
        parts = re.split(r'[%s]+' % self.sep, norm_path)
        retval = self.join(*parts[0:-1])
        return retval

    def _verify_parent_folder_exists(self, path):
        parent_path = self.dirname(path)
        if parent_path != self.sep:
            parent_obj = self.info_path(parent_path)
            if parent_obj is None:
                # perhaps this should separate "FileNotFound" and "non-folder parent exists"
                # and raise different exceptions
                raise CloudFileNotFoundError(parent_path)
            if parent_obj.otype != DIRECTORY:
                raise CloudFileExistsError(parent_path)
