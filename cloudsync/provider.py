"""
Module exports the 'Provider' abstract base class as well as the 'Hash', 'Cursor' and 'Creds' types
"""
from abc import ABC, abstractmethod
import re
import os
import logging
import random
import time
from dataclasses import dataclass
from typing import Generator, Optional, List, Union, Tuple, Dict, BinaryIO

from .types import OInfo, DIRECTORY, DirInfo, Any
from .exceptions import CloudFileNotFoundError, CloudFileExistsError, CloudTokenError, CloudNamespaceError, \
    CloudRootMissingError
from .oauth import OAuthConfig, OAuthProviderInfo
from .event import Event

log = logging.getLogger(__name__)


# user-defined types.  must be serializable via msgpack and comparable
# mypy doesn't support cyclic definitions yet...
Hash = Union[Dict[str, 'Hash'], Tuple['Hash', ...], str, int, bytes, float, None]          # type: ignore
Cursor = Union[Dict[str, 'Cursor'], Tuple['Cursor', ...], str, int, bytes, float, None]    # type: ignore
Creds = Dict[str, Union[str, int]]

CONNECTION_NOT_NEEDED = "connection-not-needed"

__all__ = ["Provider", "Namespace", "Creds", "Hash", "Cursor", "CONNECTION_NOT_NEEDED"]

@dataclass
class Namespace:
    """
    Base class representing a namespace (drive).

    Providers that support this concept should derive from this class as necessary.
    """
    name: str
    id: str

    @property
    def is_parent(self) -> bool:
        """
        Some providers support hierarchical Namespaces.
        """
        return False

    @property
    def shared_paths(self) -> List[str]:
        """
        Should only be populated when access to the namespace is limited.

        For example, user A has no access to user B's personal namespace,
        unless user B explicitly shared one or more files/folders with user A.
        """
        return []

    def __str__(self):
        return self.name


class Provider(ABC):                    # pylint: disable=too-many-public-methods
    """
    File storage provider.

    Override this to implement a provider capable of using the sync engine.

    Implementors are responsible for normalizing behavior, errors thrown, any needed caching.

    Some helpers are provided in this base class for oauth and  path manipulation.
    """

    # pylint: disable=multiple-statements
    name: str = None                          ; """Provider name"""
    sep: str = '/'                            ; """Path delimiter"""
    alt_sep: str = '\\'                       ; """Alternate path delimiter"""
    oid_is_path: bool = False                 ; """Objects stored in cloud are only referenced by path"""
    case_sensitive: bool = True               ; """Provider is case sensitive"""
    win_paths: bool = False                   ; """C: drive letter stuff needed for paths"""
    default_sleep: float = 0.01               ; """Per event loop sleep time"""
    test_root: str = '/'                      ; """Root folder to use during provider tests"""
    _root_path: Optional[str] = None          ; """Root path to use for syncing, event filtering, etc."""
    _root_oid: Optional[str] = None           ; """Root oid to use for syncing, event filtering, etc."""
    _oauth_info: OAuthProviderInfo = None     ; """OAuth providers can set this as a class variable"""
    _oauth_config: OAuthConfig = None         ; """OAuth providers can set this in init"""
    _listdir_page_size: Optional[int] = None  ; """Used for testing listdir"""

    # these are defined here for testing purposes only
    # providers setting these values will have them overridden and used for
    # multipart upload tests
    large_file_size: int = 0                  ; """Used for testing providers with separate large file handling"""
    upload_block_size: int = 0                ; """Used for testing providers with separate large file handling"""

    connection_id: Optional[str] = None       ; """Must remain constant between logins and must be unique to the login"""
    _creds: Optional[Any] = None              ; """Base class helpers to store creds"""
    __connected = False                       ; """Base class helper to fake a connection"""
    # pylint: enable=multiple-statements

    @abstractmethod
    def _api(self, *args, **kwargs):
        """Central function that wraps calls to the provider's api.

        Use this function on all calls that involve a network connection to the provider.

        Implmentations should catch provider specific errors and turn them into CloudException types.

        Suggestions for args can be:
               - endpoint + url params
               - a lambda with underlying provider calls

        Alternatively, _api can be written as a Guard with enter/exit code.
        """
        ...

    def get_quota(self) -> dict:    # pylint: disable=no-self-use
        """
        Returns a dict with of used (bytes), limit (bytes), optional login, and possibly other provider-specific info
        """
        return {"used": 0.0, "limit": 0.0, "login": None}

    def connect_impl(self, creds) -> str:  # pylint: disable=unused-argument
        """Connection implementation.

        Some providers don't need connections, so just don't implement/overload this method.

        Returns:
            Unique connection id that should be the same each time the same user connects.
            A combination of a provider name and a login/userid could be sufiicient, but
            it is suggested to use a provider specific identity, if available.
        """
        return self.connection_id or CONNECTION_NOT_NEEDED

#    @final                             # uncomment when 3.8 is lowest supported
    def connect(self, creds):
        """Connect to provider.

        Generally providers should overload connect_impl, instead.
        """
        log.debug("connect %s (%s)", self.name, self.connection_id)
        self._creds = creds
        new_id = self.connect_impl(creds)
        if self.connection_id:
            if self.connection_id != new_id:
                self.disconnect()
                raise CloudTokenError("Cannot connect with mismatched credentials")
        else:
            self.connection_id = new_id
        self.__connected = True
        assert self.connected
        self._validate_root(self._root_path, self._root_oid)

    def set_root(self, root_path=None, root_oid=None):
        """Set sync root path and oid. Once set, these values cannot be changed."""
        log.debug("set_root for %s - %s - %s", self.name, root_path, root_oid)
        if self._root_path and self._root_oid:
            if self.paths_match(self._root_path, root_path) or self._root_oid == root_oid:
                return (self._root_path, self._root_oid)
            raise ValueError("Sync root already set and cannot be changed")
        if not root_path and not root_oid:
            return (None, None)
        (self._root_path, self._root_oid) = self._validate_root(root_path, root_oid)
        return (self._root_path, self._root_oid)

    def _validate_root(self, root_path, root_oid):
        if root_oid:
            # prefer root_oid
            info = self.info_oid(root_oid)
            if not info:
                raise CloudRootMissingError(f"Failed to get info for root oid: {root_oid}")
            if info.otype != DIRECTORY:
                raise CloudRootMissingError(f"Root oid is not a directory: {root_oid} => {info.path}")
            if root_path and not self.paths_match(root_path, info.path):
                raise CloudRootMissingError(f"Root oid/path mismatch: {root_path} - {info.path}")
            root_path = info.path
        elif root_path:
            # got root_path only
            info = self.info_path(root_path)
            if info and info.otype != DIRECTORY:
                raise CloudRootMissingError(f"Root path is not a directory: {root_path}")
            root_oid = info.oid if info else self.mkdir(root_path)
        return (root_path, root_oid)

    @property
    def root_path(self) -> Optional[str]:
        """The root path, if any"""
        return self._root_path

    @property
    def root_oid(self) -> Optional[str]:
        """The root oid, if any"""
        return self._root_oid

    def set_creds(self, creds):
        """Set credentials without connecting."""
        self._creds = creds

    def reconnect(self):
        """Reconnect to provider, using existing creds.

        If a provider was previously connected, it should retain the creds used.
        This function should restore the connection if the creds are still valid

        Raises:
            CloudDisconnectedError on failure
        """
        connected = self.__connected
        if not connected:
            self.connect(self._creds)

    def disconnect(self):
        """Invalidates current connection, closes sockets, etc.
        """
        self.__connected = False

    @property
    def connected(self):
        """True if connected, false if not.

        If False, any use of the provider except the connect() function,
        must raise a CloudDisconnectedError
        """
        return self.connection_id is not None and self.__connected

    def authenticate(self) -> Creds:
        """Authenticate a connection.

        Returns:
            Creds: A JSON serializable object that can be used to log in.

        Raises:
                CloudTokenError on failure
        """
        if self._oauth_info:
            try:
                self._oauth_config.start_auth(self._oauth_info.auth_url, self._oauth_info.scopes)
                token = self._oauth_config.wait_auth(self._oauth_info.token_url)
            except Exception as e:
                log.error("oauth error %s", repr(e))
                self.disconnect()
                raise CloudTokenError(repr(e))

            return {"refresh_token": token.refresh_token,
                    "access_token": token.access_token}
        raise NotImplementedError()

    def interrupt_auth(self):
        """Iterrupt/stop a blocking authentication call."""
        if self._oauth_config:
            self._oauth_config.shutdown()
        else:
            raise NotImplementedError()

    @property
    @abstractmethod
    def latest_cursor(self) -> Cursor:
        """Get the latest cursor as of now."""
        ...

    @property
    @abstractmethod
    def current_cursor(self) -> Cursor:
        """Get the current cursor for the events generator"""
        ...

    @current_cursor.setter
    def current_cursor(self, val: Cursor) -> None:  # pylint: disable=no-self-use, unused-argument
        """Get the current cursor for the events generator"""
        ...

    @abstractmethod
    def events(self) -> Generator["Event", None, None]:
        """Yields events, possibly forever.

        If stopped, the event poller will sleep for self.default_sleep, and call this again.
        """
        ...

    @abstractmethod
    def upload(self, oid, file_like: BinaryIO, metadata=None) -> 'OInfo':
        """Upload a filelike to an existing object id, optionally setting metadata"""
        ...

    @abstractmethod
    def create(self, path, file_like: BinaryIO, metadata=None) -> 'OInfo':
        """Create a file at the specified path, setting contents and optionally setting metadata"""
        ...

    @abstractmethod
    def download(self, oid, file_like: BinaryIO):
        """Get the bytes of a specified object id"""
        ...

    @abstractmethod
    def rename(self, oid, path) -> str:
        """Rename an object to specified path"""
        # TODO: test that a renamed file can be renamed again
        # TODO: test that renaming a folder renames the children in the state file
        ...

    @abstractmethod
    def mkdir(self, path) -> str:
        """Create a folder"""
        ...

    @abstractmethod
    def delete(self, oid):
        """Delete an object"""
        ...
        ...

    @abstractmethod
    def exists_oid(self, oid) -> bool:
        """Returns true of object exists with specified oid"""
        return self.info_oid(oid) is not None

    @abstractmethod
    def exists_path(self, path) -> bool:
        """Returns true of object exists at the specified path"""
        return self.info_path(path) is not None

    @abstractmethod
    def listdir(self, oid) -> Generator[DirInfo, None, None]:
        """Yield one entry for each file at the directory pointed to by the specified object id"""
        ...

    # override this if your implementation is more efficient
    def hash_oid(self, oid) -> Hash:
        """Returns a provider specific hash associated with the object referred to"""
        info = self.info_oid(oid)
        return info.hash if info else None

    @abstractmethod
    def hash_data(self, file_like: BinaryIO) -> Hash:
        """Returns a provider specific hash from data"""
        ...

    @abstractmethod
    def info_path(self, path: str, use_cache=True) -> Optional[OInfo]:
        """Returns info for an object at a path, or None if not found"""
        ...

    @abstractmethod
    def info_oid(self, oid: str, use_cache=True) -> Optional[OInfo]:
        """Returns info for an object with specified oid, or None if not found"""
        ...

    def list_ns(self, recursive: bool = True, parent: Namespace = None) -> List[Namespace]:   # pylint: disable=no-self-use,unused-argument
        """Yield one entry for each namespace supported, or None if namespaces are not needed"""
        return None

    @property
    def namespace(self) -> Optional[Namespace]:            # pylint: disable=no-self-use
        """Some providers have multiple 'namespaces', that can be listed and changed.

        Cannot be set when not connected.
        """
        return None

    @namespace.setter
    def namespace(self, ns: Namespace):                    # pylint: disable=no-self-use
        raise CloudNamespaceError("This provider does not support namespaces")

    @property
    def namespace_id(self) -> Optional[str]:               # pylint: disable=no-self-use
        """Unique id corresponding to a namespace name.

        Can be set when not connected.
        """
        return None

    @namespace_id.setter
    def namespace_id(self, ns_id: str):                    # pylint: disable=no-self-use
        raise CloudNamespaceError("This provider does not support namespaces")

    @classmethod
    def uses_oauth(cls):
        """Return True if provider uses OAuthConfig initialization"""
        return cls._oauth_info is not None

# CONVENIENCE
    def download_path(self, path, io):
        info = self.info_path(path)
        if not info or not info.oid:
            raise CloudFileNotFoundError()
        self.download(info.oid, io)

    def listdir_path(self, path) -> Generator[DirInfo, None, None]:
        info = self.info_path(path)
        if not info:
            raise CloudFileNotFoundError()
        return self.listdir_oid(info.oid, path)

    def listdir_oid(self, oid, path=None) -> Generator[DirInfo, None, None]:
        for result in self.listdir(oid):
            if result.path is None and path is not None:
                result.path = self.join(path, result.name)
            yield result

    def rmtree(self, oid):
        """Recursively remove all folders including the folder/file specified.

        Override this if your provider has a more efficient implementation.
        """
        try:
            for info in self.listdir(oid):
                if info.otype == DIRECTORY:
                    self.rmtree(info.oid)
                else:
                    self.delete(info.oid)
            self.delete(oid)
        except CloudFileNotFoundError:
            pass

    def _walk(self, path, oid, recursive):
        try:
            for ent in self.listdir(oid):
                current_path = self.join(path, ent.name)
                event = Event(otype=ent.otype, oid=ent.oid, path=current_path, hash=ent.hash, exists=True, mtime=time.time())
                # log.debug("walk %s", event)
                yield event
                if ent.otype == DIRECTORY and recursive:
                    yield from self._walk(current_path, ent.oid, recursive)
        except CloudFileNotFoundError:
            # folders that disappear are not in the walk
            pass

    def walk(self, path, recursive=True):
        """List all files recursively, yielded as events"""
        info = self.info_path(path)
        if not info:
            raise CloudFileNotFoundError(path)
        yield from self._walk(path, info.oid, recursive)

    def walk_oid(self, oid, recursive=True):
        """List all files recursively, yielded as events"""
        info = self.info_oid(oid)
        if not info:
            raise CloudFileNotFoundError(oid)
        yield from self._walk(info.path, info.oid, recursive)


# HELPER
    @classmethod
    def join(cls, *paths):
        """
        Joins a list of path strings in a provider-specific manner.

        Args:
            paths: zero or more paths
        """
        rl: List[str] = []
        for path in paths:
            if not path:
                continue

            if isinstance(path, str):
                path = cls.normalize_path_separators(path)
                if path and path != cls.sep:
                    rl += [path.strip(cls.sep)]
                continue

            for sub_path in path:
                sub_path = cls.normalize_path_separators(sub_path)
                if sub_path and sub_path != cls.sep:
                    rl += [sub_path.strip(cls.sep)]

        if not rl:
            return cls.sep

        res = cls.sep.join(rl)

        if not cls.win_paths or res[1] != ':':
            res = cls.sep + res

        return res

    def split(self, path):
        """Splits a path into a dirname, filename, just like 1os.path.split()1"""
        path = self.normalize_path_separators(path)
        index = path.rfind(self.sep)
        if index == -1:
            return "", path
        if index == 0:
            return self.sep, path[index + 1:]
        return path[:index], path[index+1:]

    @classmethod
    def normalize_path_separators(cls, path: str):
        """Normalizes path separators only.

        Replaces alternate separators with primary, strips separators from end of path string.
        """
        if path:
            path = path.replace(cls.alt_sep, cls.sep) if cls.alt_sep else path
            path = path.rstrip(cls.sep) if path != cls.sep else path
        return path

    def normalize_path(self, path: str, for_display: bool = False):
        """Used internally for comparing paths in a case and sep insensitive manner, as appropriate.

        Args:
            path: the path to normalize
            for_display: when true, preserve case of path's leaf node
        """
        path = self.normalize_path_separators(path)
        parts = re.split(f"[{re.escape(self.sep)}]+", path)
        norm_path = self.join(*parts)

        if self.case_sensitive:
            return norm_path
        elif for_display:
            return self.join(self.dirname(norm_path).lower(), self.basename(norm_path))
        return norm_path.lower()

    def is_subpath(self, folder, target, strict=False):
        """True if the target is within the folder.

        Args:
            folder: the directory
            target: the potential sub-file or folder
            strict: whether to return True if folder==target
        """
        if not folder or not target:
            return False

        folder_full = self.normalize_path_separators(folder)
        target_full = self.normalize_path_separators(target)

        # .lower() instead of normcase because normcase will also mess with separators
        if not self.case_sensitive:
            folder_full_case = folder_full.lower()
            target_full_case = target_full.lower()
        else:
            folder_full_case = folder_full
            target_full_case = target_full

        # target is same as folder, or target is a subpath (ensuring separator is there for base)
        if folder_full_case == target_full_case:
            return False if strict else self.sep
        if folder_full_case == self.sep and target_full_case[0] == self.sep:
            return target_full
        elif len(target_full) > len(folder_full) and target_full[len(folder_full)] == self.sep:
            if target_full_case.startswith(folder_full_case):
                return target_full[len(folder_full):]
            else:
                return False
        return False

    def is_subpath_of_root(self, target, strict=False):
        """True if the target is within the root folder.

        Args:
            folder: the directory
            target: the potential sub-file or folder
            strict: whether to return True if folder==root
        """
        return self.is_subpath(self._root_path, target, strict)

    def replace_path(self, path, from_dir, to_dir):
        """Replaces from_dir with to_dir in path, but only if from_dir `is_subpath` of path."""
        relative = self.is_subpath(from_dir, path)
        if relative:
            return self.normalize_path_separators(to_dir) + (relative if relative != self.sep else "")
        raise ValueError("replace_path used without subpath")

    def paths_match(self, patha, pathb, for_display=False):
        """True if two paths are equal, uses normalize_path()."""
        if patha is None and pathb is None:
            return True
        elif patha is None or pathb is None:
            return False

        return self.normalize_path(patha, for_display) == self.normalize_path(pathb, for_display)

    def dirname(self, path: str):
        """Just like `os.dirname`, but for provider paths."""
        ret, _ = self.split(path)
        return ret

    def basename(self, path: str):
        """Just like `os.basename`, but for provider paths."""
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

    def globalize_oid(self, oid: str) -> str:       # pylint: disable=no-self-use
        """Converts an oid that may be account specific to one that can be used in other accounts."""
        return oid

    def localize_oid(self, global_oid: str):        # pylint: disable=no-self-use
        """Converts a globalized oid to one that can be used locally.

        All regular provider functions use 'local oids' only unless otherwise specified.
        """
        return global_oid

    def mkdirs(self, path):
        """Makes a directory and intervening directories, returns the oid of the leaf"""
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

# TEST ################################################
    def test_short_poll_only(self, short_poll_only: bool):  # pylint: disable=unused-argument, no-self-use
        pass

    @classmethod
    def test_instance(cls):
        """Override to enable CI testing of your class, see oauth_test_instance code for an example

        Returns:
            Provider: an instance of an provider, with "creds" set to the creds blob
        """
        if cls._oauth_info is not None:
            # pull environment info based on class name prefix
            return cls.oauth_test_instance(prefix=cls.name.upper())             # pylint: disable=no-member
        else:
            # no connection needed
            cls._test_creds: Dict[str, str] = None            # type: ignore
            return cls()

    def _clear_cache(self, *, oid=None, path=None):  # pylint: disable=unused-argument, no-self-use
        # override this method if the provider implements a cache, to permit the internal cache to be cleared on demand
        # the _clear_cache method in the subclass should return True
        return False

    @classmethod
    def oauth_test_instance(cls, prefix: str, token_key="refresh_token", token_sep="|", port_range: Tuple[int, int] = None, host_name=None):
        """Helper function for oauth providers.

        Args:
            prefix: environment variable prefix
            token_key: creds dict key
            token_sep: multi-env var token separator
            port_range: if any, specify tuple
        """

        tokens = os.environ.get("%s_TOKEN" % prefix).split(token_sep)
        token = tokens[random.randrange(0, len(tokens))]

        if token.startswith("file:"):
            token = open(token[5:]).read()

        creds = {
            token_key: token,
        }
        cls._test_creds = creds                                          # type: ignore
        return cls(OAuthConfig(                                         # type: ignore
            app_id=os.environ.get("%s_APP_ID" % prefix),
            app_secret=os.environ.get("%s_APP_SECRET" % prefix),
            host_name=host_name,
            port_range=port_range))
