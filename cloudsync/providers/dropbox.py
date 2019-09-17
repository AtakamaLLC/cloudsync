import io
import os
import time
import logging
import threading
from hashlib import sha256
import webbrowser
from typing import Generator, Optional, Dict, Any, Union
from os import urandom
from base64 import urlsafe_b64encode as u_b64enc
import requests
import arrow

import dropbox
from dropbox import Dropbox, exceptions, files, DropboxOAuth2Flow
from dropbox.oauth import OAuth2FlowResult
from cloudsync.oauth_config import OAuthConfig
from cloudsync import Provider, OInfo, DIRECTORY, FILE, NOTKNOWN, Event, DirInfo

from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError, \
    CloudFileNotFoundError, CloudTemporaryError, CloudFileExistsError, CloudCursorError

log = logging.getLogger(__name__)
logging.getLogger('dropbox').setLevel(logging.INFO)

class _FolderIterator:
    def __init__(self, api, path, *, recursive, cursor=None):
        self.api = api
        self.path = path
        self.ls_res = None

        if not cursor:
            self.ls_res = self.api('files_list_folder',
                                   path=self.path,
                                   recursive=recursive,
                                   limit=200)
        else:
            self.ls_res = self.api('files_list_folder_continue',
                                   cursor)

    def __iter__(self):
        return self

    def __next__(self):
        if self.ls_res:
            if not self.ls_res.entries and self.ls_res.has_more:
                self.ls_res = self.api(
                    'files_list_folder_continue', self.ls_res.cursor)

            if self.ls_res and self.ls_res.entries:
                ret = self.ls_res.entries.pop()
                ret.cursor = self.ls_res.cursor
                return ret
        raise StopIteration()

    @property
    def cursor(self):
        return self.ls_res and self.ls_res.cursor


class DropboxProvider(Provider):         # pylint: disable=too-many-public-methods, too-many-instance-attributes
    case_sensitive = False
    default_sleep = 15

    _max_simple_upload_size = 15 * 1024 * 1024
    _upload_block_size = 10 * 1024 * 1024
    name = "Dropbox"
    _redir = 'urn:ietf:wg:oauth:2.0:oob'

    def __init__(self, oauth_config: Optional[OAuthConfig] = None):
        super().__init__()
        self.__root_id = None
        self.__cursor = None
        self.__creds = None
        self.client = None
        self.api_key = None
        self._csrf = None
        self._flow = None
        self.user_agent = 'cloudsync/1.0'
        self.mutex = threading.Lock()
        self._session: Dict[Any, Any] = {}
        self._oauth_config = oauth_config if oauth_config else OAuthConfig()
        self._oauth_done = threading.Event()

    @property
    def connected(self):
        return self.client is not None

    def get_display_name(self):
        return self.name

    def initialize(self):
        self._csrf = u_b64enc(urandom(32))
        key = 'objo7li90yqmnfi'
        secret = '9usaijv8g3fsqsl'
        log.debug('Initializing Dropbox with manual mode=%s', self._oauth_config.manual_mode)
        if not self._oauth_config.manual_mode:
            try:
                self._oauth_config.oauth_redir_server.run(
                    on_success=self._on_oauth_success,
                    on_failure=self._on_oauth_failure,
                    use_predefined_ports=True,
                )
                self._flow = DropboxOAuth2Flow(consumer_key=key,
                                               consumer_secret=secret,
                                               redirect_uri=self._oauth_config.oauth_redir_server.uri('/auth/'),
                                               session=self._session,
                                               csrf_token_session_key=self._csrf,
                                               locale=None)
            except OSError:
                log.exception('Unable to use redir server. Falling back to manual mode')
                self._oauth_config.manual_mode = False
        if self._oauth_config.manual_mode:
            self._flow = DropboxOAuth2Flow(consumer_key=key,
                                          consumer_secret=secret,
                                          redirect_uri=self._redir,
                                          session=self._session,
                                          csrf_token_session_key=self._csrf,
                                          locale=None)
        url = self._flow.start()
        self._oauth_done.clear()
        webbrowser.open(url)

        return url

    def interrupt_oauth(self):
        if not self._oauth_config.manual_mode:
            self._oauth_config.oauth_redir_server.shutdown()  # ApiServer shutdown does not throw  exceptions
        self._flow = None
        self._oauth_done.clear()

    def _on_oauth_success(self, auth_dict):
        if auth_dict and 'state' in auth_dict and isinstance(auth_dict['state'], list):
            auth_dict['state'] = auth_dict['state'][0]
        try:
            res: OAuth2FlowResult = self._flow.finish(auth_dict)
            self.api_key = res.access_token
            self._oauth_done.set()
        except Exception:
            log.exception('Authentication failed')
            raise

    def _on_oauth_failure(self, err):
        log.error("oauth failure: %s", err)
        self._oauth_done.set()

    def authenticate(self):
        try:
            self.initialize()
            self._oauth_done.wait()
            return {"key": self.api_key,}
        finally:
            if not self._oauth_config.manual_mode:
                self._oauth_config.oauth_redir_server.shutdown()

    def get_quota(self):
        space_usage = self._api('users_get_space_usage')
        account = self._api('users_get_current_account')
        if space_usage.allocation.is_individual():
            used = space_usage.used
            allocated = space_usage.allocation.get_individual().allocated
        else:
            team_allocation = space_usage.allocation.get_team()
            used, allocated = team_allocation.used, team_allocation.allocated

        res = {
            'used': used,
            'total': allocated,
            'login': account.email,
            'uid': account.account_id[len('dbid:'):]
        }

        return res

    def reconnect(self):
        self.connect_or_authenticate(self.__creds)

    def connect(self, creds):
        log.debug('Connecting to dropbox')
        if not self.client:
            self.__creds = creds
            api_key = creds.get('key', self.api_key)

            if not api_key:
                raise CloudTokenError()

            with self.mutex:
                self.client = Dropbox(api_key)

            try:
                quota = self.get_quota()
                self.connection_id = quota['login']
            except Exception as e:
                self.disconnect()
                log.exception("error connecting %s", e)
                if isinstance(e, exceptions.AuthError):
                    raise CloudTokenError()
                raise CloudDisconnectedError()
            self.api_key = api_key

    def _api(self, method, *args, **kwargs):  # pylint: disable=arguments-differ, too-many-branches, too-many-statements
        if not self.client:
            raise CloudDisconnectedError("currently disconnected")

        log.debug("_api: %s (%s %s)", method, args, kwargs)

        with self.mutex:
            try:
                return getattr(self.client, method)(*args, **kwargs)
            except exceptions.ApiError as e:
                inside_error: Union[files.LookupError, files.WriteError]

                if isinstance(e.error, (files.ListFolderError, files.GetMetadataError, files.ListRevisionsError)):
                    if e.error.is_path() and isinstance(e.error.get_path(), files.LookupError):
                        inside_error = e.error.get_path()
                        if inside_error.is_malformed_path():
                            log.debug('Malformed path when executing %s(%s %s) : %s',
                                      method, args, kwargs, e)
                            raise CloudFileNotFoundError(
                                'Malformed path when executing %s(%s)' % (method, kwargs))
                        if inside_error.is_not_found():
                            log.debug('file not found %s(%s %s) : %s',
                                      method, args, kwargs, e)
                            raise CloudFileNotFoundError(
                                'File not found when executing %s(%s)' % (method, kwargs))

                if isinstance(e.error, files.DeleteError):
                    if e.error.is_path_lookup():
                        inside_error = e.error.get_path_lookup()
                        if inside_error.is_not_found():
                            log.debug('file not found %s(%s %s) : %s',
                                      method, args, kwargs, e)
                            raise CloudFileNotFoundError(
                                'File not found when executing %s(%s)' % (method, kwargs))

                if isinstance(e.error, files.RelocationError):
                    if e.error.is_from_lookup():
                        inside_error = e.error.get_from_lookup()
                        if inside_error.is_not_found():
                            log.debug('file not found %s(%s %s) : %s',
                                      method, args, kwargs, e)
                            raise CloudFileNotFoundError(
                                'File not found when executing %s(%s,%s)' % (method, args, kwargs))
                    if e.error.is_to():
                        inside_error = e.error.get_to()
                        if inside_error.is_conflict():
                            raise CloudFileExistsError(
                                'File already exists when executing %s(%s)' % (method, kwargs))
                        log.debug("here")

                if isinstance(e.error, files.CreateFolderError):
                    if e.error.is_path() and isinstance(e.error.get_path(), files.WriteError):
                        inside_error = e.error.get_path()
                        if inside_error.is_conflict():
                            raise CloudFileExistsError(
                                'File already exists when executing %s(%s)' % (method, kwargs))
            except (exceptions.InternalServerError, exceptions.RateLimitError, requests.exceptions.ReadTimeout):
                raise CloudTemporaryError()
            except dropbox.stone_validators.ValidationError as e:
                log.debug("f*ed up api error: %s", e)
                if "never created" in str(e):
                    raise CloudFileNotFoundError()
                if "did not match" in str(e):
                    log.warning("oid error %s", e)
                    raise CloudFileNotFoundError()
                raise
            except requests.exceptions.ConnectionError as e:
                log.exception('api error handled exception %s:%s',
                              "dropbox", e.__class__.__name__)
                self.disconnect()
                raise CloudDisconnectedError()

    @property
    def root_id(self):
        return ""

    def disconnect(self):
        self.client = None

    @property
    def latest_cursor(self):
        res = self._api('files_list_folder_get_latest_cursor',
                        self.root_id, recursive=True, include_deleted=True, limit=200)
        if res:
            return res.cursor
        else:
            return None

    @property
    def current_cursor(self):
        if not self.__cursor:
            self.__cursor = self.latest_cursor
        return self.__cursor

    @current_cursor.setter
    def current_cursor(self, val):
        if val is None:
            val = self.latest_cursor
        if not isinstance(val, str) and val is not None:
            raise CloudCursorError(val)
        self.__cursor = val

    def _events(self, cursor, path=None):  # pylint: disable=too-many-branches
        if path and path != "/":
            info = self.info_path(path)
            if not info:
                raise CloudFileNotFoundError(path)
            oid = info.oid
        else:
            oid = self.root_id

        for res in _FolderIterator(self._api, oid, recursive=True, cursor=cursor):
            exists = True

            log.debug("event %s", res)

            if isinstance(res, files.DeletedMetadata):
                # dropbox doesn't give you the id that was deleted
                # we need to get the ids of every revision
                # then find out which one was the latest before the deletion time
                # then get the oid for that

                revs = self._api('files_list_revisions',
                                 res.path_lower, limit=10)
                if revs is None:
                    # dropbox will give a 409 conflict if the revision history was deleted
                    # instead of raising an error, this gets converted to revs==None
                    log.info("revs is none for %s %s", oid, path)
                    continue

                log.debug("revs %s", revs)
                deleted_time = revs.server_deleted
                if deleted_time is None:  # not really sure why this happens, but this event isn't useful without it
                    log.error("revs %s has no deleted time?", revs)
                    continue
                latest_time = None
                for ent in revs.entries:
                    assert ent.server_modified is not None
                    if ent.server_modified <= deleted_time and \
                            (latest_time is None or ent.server_modified >= latest_time):
                        oid = ent.id
                        latest_time = ent.server_modified
                if not oid:
                    log.error(
                        "skipping deletion %s, because we don't know the oid", res)
                    continue

                exists = False
                otype = NOTKNOWN
                ohash = None
            elif isinstance(res, files.FolderMetadata):
                otype = DIRECTORY
                ohash = None
                oid = res.id
            else:
                otype = FILE
                ohash = res.content_hash
                oid = res.id

            path = res.path_display
            event = Event(otype, oid, path, ohash, exists, time.time())
            yield event
            if getattr(res, "cursor", False):
                self.__cursor = res.cursor

    def events(self) -> Generator[Event, None, None]:
        yield from self._events(self.current_cursor)

    def walk(self, path, since=None):
        yield from self._events(None, path=path)

    def listdir(self, oid) -> Generator[DirInfo, None, None]:
        yield from self._listdir(oid, recursive=False)

    def _listdir(self, oid, *, recursive) -> Generator[DirInfo, None, None]:
        info = self.info_oid(oid)
        for res in _FolderIterator(self._api, oid, recursive=recursive):
            if isinstance(res, files.DeletedMetadata):
                continue
            if isinstance(res, files.FolderMetadata):
                otype = DIRECTORY
                ohash = None
            else:
                otype = FILE
                ohash = res.content_hash
            path = res.path_display
            oid = res.id
            relative = self.is_subpath(info.path, path).lstrip("/")
            if relative:
                yield DirInfo(otype, oid, ohash, path, name=relative)

    def create(self, path: str, file_like, metadata=None) -> OInfo:
        self._verify_parent_folder_exists(path)
        if self.exists_path(path):
            raise CloudFileExistsError(path)
        return self._upload(path, file_like, metadata)

    def upload(self, oid: str, file_like, metadata=None) -> OInfo:
        if oid.startswith(self.sep):
            raise CloudFileNotFoundError("Called upload with a path instead of an OID: %s" % oid)
        if not self.exists_oid(oid):
            raise CloudFileNotFoundError(oid)
        return self._upload(oid, file_like, metadata)

    def _upload(self, oid, file_like, metadata=None) -> OInfo:
        res = None
        metadata = metadata or {}

        file_like.seek(0, io.SEEK_END)
        size = file_like.tell()
        file_like.seek(0)

        if size < self._max_simple_upload_size:
            res = self._api('files_upload', file_like.read(),
                            oid, mode=files.WriteMode('overwrite'))
        else:
            cursor = None

            while True:
                data = file_like.read(self._upload_block_size)
                if not data:
                    if cursor:
                        local_mtime = arrow.get(metadata.get('mtime', time.time())).datetime
                        commit = files.CommitInfo(path=oid,
                                                  mode=files.WriteMode.overwrite,
                                                  autorename=False,
                                                  client_modified=local_mtime,
                                                  mute=True)
                        res = self._api(
                            'files_upload_session_finish',
                            data, cursor, commit
                        )
                    break
                if not cursor:
                    self._api('files_upload_session_start', data)
                    cursor = files.UploadSessionCursor(
                        res.session_id, len(data))
                else:
                    self._api('files_upload_session_append_v2',
                              data, cursor)
                    cursor.offset += len(data)

        if res is None:
            raise CloudFileExistsError()

        ret = OInfo(otype=FILE, oid=res.id, hash=res.content_hash, path=res.path_display)
        log.debug('upload result is %s', ret)
        return ret

    def download(self, oid, file_like):
        ok = self._api('files_download', oid)
        if not ok:
            raise CloudFileNotFoundError()
        res, content = ok
        for data in content.iter_content(self._upload_block_size):
            file_like.write(data)
        return OInfo(otype=FILE, oid=oid, hash=res.content_hash, path=res.path_display)

    def _attempt_rename_folder_over_empty_folder(self, info: OInfo, path: str) -> None:
        if info.otype != DIRECTORY:
            raise CloudFileExistsError(path)
        possible_conflict = self.info_path(path)
        if possible_conflict.otype == DIRECTORY:
            try:
                next(self._listdir(possible_conflict.oid, recursive=False))
                raise CloudFileExistsError("Cannot rename over non-empty folder %s" % path)
            except StopIteration:
                pass  # Folder is empty, rename over it no problem
            self.delete(possible_conflict.oid)
            self._api('files_move_v2', info.oid, path)
            return
        else:  # conflict is a file, and we already know that the rename is on a folder
            raise CloudFileExistsError(path)

    def rename(self, oid, path):
        try:
            self._api('files_move_v2', oid, path)
        except CloudFileExistsError:
            old_info = self.info_oid(oid)

            if self.paths_match(old_info.path, path):
                new_info = self.info_path(path)
                if oid == new_info.oid and old_info.path != path:
                    temp_path = path + "." + os.urandom(16).hex()
                    self._api('files_move_v2', oid, temp_path)
                    self.rename(oid, path)
                return oid

            if old_info.otype == DIRECTORY:
                self._attempt_rename_folder_over_empty_folder(old_info, path)
            else:
                raise
        return oid

    @staticmethod
    def hash_data(file_like) -> str:
        # get a hash from a filelike that's the same as the hash i natively use
        binstr = b''
        while True:
            data = file_like.read(4 * 1024 * 1024)
            if not data:
                break
            binstr += sha256(data).digest()
        return sha256(binstr).hexdigest()

    def mkdir(self, path, metadata=None) -> str:    # pylint: disable=arguments-differ, unused-argument
        # TODO: check if a regular filesystem lets you mkdir over a non-empty folder...
        self._verify_parent_folder_exists(path)
        if self.exists_path(path):
            info = self.info_path(path)
            if info.otype == FILE:
                raise CloudFileExistsError()
            log.debug("Skipped creating already existing folder: %s", path)
            return info.oid
        res = self._api('files_create_folder_v2', path)
        log.debug("dbx mkdir %s", res)
        res = res.metadata
        return res.id

    def delete(self, oid):
        info = self.info_oid(oid)
        if not info:
            return  # file doesn't exist already...
        if info.otype == DIRECTORY:
            try:
                next(self._listdir(oid, recursive=False))
                raise CloudFileExistsError("Cannot delete non-empty folder %s:%s" % (oid, info.path))
            except StopIteration:
                pass  # Folder is empty, delete it no problem
        try:
            self._api('files_delete_v2', oid)
        except CloudFileNotFoundError:  # shouldn't happen because we are checking above...
            return

    def exists_oid(self, oid) -> bool:
        return bool(self.info_oid(oid))

    def info_path(self, path: str) -> Optional[OInfo]:
        if path == "/":
            return OInfo(DIRECTORY, "", None, "/")

        try:
            log.debug("res info path %s", path)
            res = self._api('files_get_metadata', path)
            log.debug("res info path %s", res)

            oid = res.id
            if oid[0:3] != 'id:':
                log.warning("invalid oid %s from path %s", oid, path)

            if isinstance(res, files.FolderMetadata):
                otype = DIRECTORY
                fhash = None
            else:
                otype = FILE
                fhash = res.content_hash

            path = res.path_display or path
            return OInfo(otype, oid, fhash, path)
        except CloudFileNotFoundError:
            return None

    def exists_path(self, path) -> bool:
        return self.info_path(path) is not None

    def info_oid(self, oid, use_cache=True) -> Optional[OInfo]:
        if oid == "":
            otype = DIRECTORY
            fhash = None
            path = "/"
        else:
            try:
                res = self._api('files_get_metadata', oid)
                log.debug("res info oid %s", res)
                path = res.path_display
                if isinstance(res, files.FolderMetadata):
                    otype = DIRECTORY
                    fhash = None
                else:
                    otype = FILE
                    fhash = res.content_hash
            except CloudFileNotFoundError:
                return None
        return OInfo(otype, oid, fhash, path)
