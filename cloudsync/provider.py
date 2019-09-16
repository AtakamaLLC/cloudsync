from abc import ABC, abstractmethod
import os
import re
import logging
from typing import TYPE_CHECKING, Generator, Optional, Union, List, Any

from cloudsync.types import OInfo, DIRECTORY, DirInfo
from cloudsync.exceptions import CloudFileNotFoundError, CloudFileExistsError, CloudTokenError
if TYPE_CHECKING:
    from cloudsync.event import Event

log = logging.getLogger(__name__)


class Provider(ABC):                    # pylint: disable=too-many-public-methods
    sep: str = '/'                      # path delimiter
    alt_sep: str = '\\'                 # alternate path delimiter
    oid_is_path: bool = False
    case_sensitive: bool = True
    win_paths: bool = False
    connection_id: Optional[str] = None
    default_sleep: float = 0.01

    @abstractmethod
    def _api(self, *args, **kwargs):
        ...

    def connect(self, creds):           # pylint: disable=unused-argument
        # some providers don't need connections, so just don't implement/overload this method
        # providers who implement connections need to set the connection_id to a value
        #   that is unique to each connection, so that connecting to this provider
        #   under multiple userid's will produce different connection_id's. One
        #   suggestion is to just set the connection_id to the user's login_id
        self.connection_id = os.urandom(16).hex()

    def reconnect(self):                # pylint: disable=no-self-use
        # reuse existing credentials and reconnect
        # raises: CloudDisconnectedError on failure
        pass

    def authenticate(self):
        # implement this method for providers that need authentication
        pass

    def connect_or_authenticate(self, creds):
        # This won't attempt oauth unless the specific failure to connect is an authentication error
        try:
            self.connect(creds)
        except CloudTokenError:
            creds = self.authenticate()  # pylint: disable=assignment-from-no-return
            self.connect(creds)
        return creds

    @property
    @abstractmethod
    def name(self):
        ...

    @abstractmethod
    def latest_cursor(self):
        ...

    @property
    @abstractmethod
    def current_cursor(self) -> Any:
        ...

    @current_cursor.setter
    def current_cursor(self, val: Any) -> None:  # pylint: disable=no-self-use, unused-argument
        ...

    @abstractmethod
    def events(self) -> Generator["Event", None, None]:
        ...

    @abstractmethod
    def walk(self, path, since=None):
        # Test that the root path does not show up in the walk
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
    def rename(self, oid, path) -> str:
        # TODO: test that a renamed file can be renamed again
        # TODO: test that renaming a folder renames the children in the state file
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

    def hash_oid(self, oid) -> Optional[bytes]:  # TODO add a test to FNFE
        info = self.info_oid(oid)
        return info.hash if info else None

    @staticmethod
    @abstractmethod
    def hash_data(file_like) -> Union[str, bytes]:
        ...

    @abstractmethod
    def info_path(self, path: str) -> Optional[OInfo]:
        ...

    @abstractmethod
    def info_oid(self, oid, use_cache=True) -> Optional[OInfo]:
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
        rl: List[str] = []
        for path in paths:
            if not path or path == cls.sep:
                continue

            if isinstance(path, str):
                rl = rl + [path.strip(cls.sep).strip(cls.alt_sep)]
                continue

            for sub_path in path:
                if sub_path is None or sub_path == cls.sep or sub_path == cls.alt_sep:
                    continue
                rl = rl + [sub_path.strip(cls.sep)]

        if not rl:
            return cls.sep

        res = cls.sep.join(rl)

        if not cls.win_paths or res[1] != ':':
            res = cls.sep + res

        return res

    def split(self, path):
        # todo cache regex
        index = path.rfind(self.sep)
        if self.alt_sep:
            index = max(index, path.rfind(self.alt_sep))

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
        if not self.case_sensitive:
            norm_path = norm_path.lower()
        return norm_path

    def is_subpath(self, folder, target, sep=None, alt_sep=None, strict=False):
        sep = sep or self.sep
        alt_sep = alt_sep or self.alt_sep
        if alt_sep:
            folder = folder.replace(alt_sep, sep)
            target = target.replace(alt_sep, sep)

        # Will return True for is-same-path in addition to target
        folder_full = str(folder)
        folder_full = folder_full.rstrip(sep)
        target_full = str(target)
        target_full = target_full.rstrip(sep)
        # .lower() instead of normcase because normcase will also mess with separators
        if not self.case_sensitive:
            folder_full_case = folder_full.lower()
            target_full_case = target_full.lower()
        else:
            folder_full_case = folder_full
            target_full_case = target_full

        # target is same as folder, or target is a subpath (ensuring separator is there for base)
        if folder_full_case == target_full_case:
            return False if strict else sep
        elif len(target_full) > len(folder_full) and target_full[len(folder_full)] == sep:
            if target_full_case.startswith(folder_full_case):
                return target_full[len(folder_full):]
            else:
                return False
        return False

    def replace_path(self, path, from_dir, to_dir):
        relative = self.is_subpath(from_dir, path)
        if relative:
            retval = to_dir + (relative if relative != self.sep else "")
            return retval if relative != "" else self.sep
        raise ValueError("replace_path used without subpath")

    def paths_match(self, patha, pathb):
        if patha is None and pathb is None:
            return True
        elif patha is None or pathb is None:
            return False

        return self.normalize_path(patha) == self.normalize_path(pathb)

    def dirname(self, path: str):
        ret, _ = self.split(path)
        return ret

    def basename(self, path: str):
        _, ret = self.split(path)
        return ret

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

    def mkdirs(self, path):
        log.debug("mkdirs %s", path)
        try:
            oid = self.mkdir(path)
            # todo update state
        except CloudFileExistsError:
            # todo: mabye CloudFileExistsError needs to have an oid and/or path in it
            # at least optionally
            info = self.info_path(path)
            if info and info.otype == DIRECTORY:
                oid = info.oid
            else:
                raise
        except CloudFileNotFoundError:
            ppath, _ = self.split(path)
            if ppath == path:
                raise
            log.debug("mkdirs parent, %s", ppath)
            unused_oid = self.mkdirs(ppath)
            try:
                oid = self.mkdir(path)
                # todo update state
            except CloudFileNotFoundError:
                # when syncing, file exists seems to hit better conflict code for these sorts of situations
                # but this is a guess.  todo: scenarios that make this happen
                raise CloudFileExistsError("f'ed up mkdir")
        return oid
