import io
import time
import logging
import threading

import requests

import arrow

import dropbox
from dropbox import Dropbox, exceptions, files

from cloudsync import Provider, OInfo, DIRECTORY, FILE, Event

from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError, CloudFileNotFoundError, CloudTemporaryError, CloudFileExistsError

log = logging.getLogger(__name__)


class DropboxInfo(OInfo):
    name = ""

    def __new__(cls, *a, name=None):
        self = super().__new__(cls, *a)
        self.name = name
        return self


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

            if self.ls_res.entries:
                ret = self.ls_res.entries.pop()
                ret.cursor = self.ls_res.cursor
                return ret
        raise StopIteration()

    @property
    def cursor(self):
        return self.ls_res and self.ls_res.cursor


class DropboxProvider(Provider):         # pylint: disable=too-many-public-methods, too-many-instance-attributes
    case_sensitive = False

    _max_simple_upload_size = 15 * 1024 * 1024
    _upload_block_size = 10 * 1024 * 1024

    def __init__(self, sync_root):
        super().__init__(sync_root)
        self.__root_id = None
        self.__sync_root_id = None
        self.__cursor = None
        self.client = None
        self.api_key = None
        self.user_agent = 'cloudsync/1.0'
        self.mutex = threading.Lock()

    @property
    def connected(self):
        return self.client is not None

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

    def connect(self, creds):
        log.debug('Connecting to dropbox')
        if not self.client:
            self.api_key = creds.get('key', self.api_key)
            if not self.api_key:
                raise CloudTokenError()

            self.client = Dropbox(self.api_key)
            try:
                self.get_quota()
            except exceptions.AuthError:
                self.disconnect()
                raise CloudTokenError()
            except Exception as e:
                log.debug("error connecting %s", e)
                self.disconnect()
                raise CloudDisconnectedError()

        if not self.sync_root_id:
            raise CloudFileNotFoundError("cant create sync root")

    def _api(self, method, *args, **kwargs):          # pylint: disable=arguments-differ, too-many-branches
        if not self.client:
            raise CloudDisconnectedError("currently disconnected")

        with self.mutex:
            try:
                return getattr(self.client, method)(*args, **kwargs)
            except exceptions.ApiError as e:
                if isinstance(e.error, (files.ListFolderError, files.GetMetadataError, files.ListRevisionsError)):
                    if e.error.is_path() and isinstance(e.error.get_path(), files.LookupError):
                        inside_error: files.LookupError = e.error.get_path()
                        if inside_error.is_not_found():
                            log.debug('Malformed path when executing %s(%s %s) : %s',
                                      method, args, kwargs, e)
                            raise CloudFileNotFoundError(
                                'Malformed path when executing %s(%s)' % (method, kwargs))
                        if inside_error.is_malformed_path():
                            log.debug('file not found %s(%s %s) : %s',
                                      method, args, kwargs, e)
                            raise CloudFileNotFoundError(
                                'File not found when executing %s(%s)' % (method, kwargs))

                if isinstance(e.error, files.DeleteError):
                    if e.error.is_path_lookup():
                        inside_error: files.LookupError = e.error.get_path_lookup()
                        if inside_error.is_not_found():
                            log.debug('file not found %s(%s %s) : %s',
                                      method, args, kwargs, e)
                            raise CloudFileNotFoundError(
                                'File not found when executing %s(%s)' % (method, kwargs))

                if isinstance(e.error, files.RelocationError):
                    if e.error.is_from_lookup():
                        inside_error: files.LookupError = e.error.get_from_lookup()
                        if inside_error.is_not_found():
                            log.debug('file not found %s(%s %s) : %s',
                                      method, args, kwargs, e)
                            raise CloudFileNotFoundError(
                                'File not found when executing %s(%s)' % (method, kwargs))
                    if e.error.is_to():
                        inside_error: files.WriteError = e.error.get_to()
                        if inside_error.is_conflict():
                            raise CloudFileExistsError(
                                'File already exists when executing %s(%s)' % (method, kwargs))
                        log.debug("here")

                if isinstance(e.error, files.CreateFolderError):
                    if e.error.is_path() and isinstance(e.error.get_path(), files.WriteError):
                        inside_error: files.WriteError = e.error.get_path()
                        if inside_error.is_conflict():
                            raise CloudFileExistsError(
                                'File already exists when executing %s(%s)' % (method, kwargs))
            except (exceptions.InternalServerError, exceptions.RateLimitError):
                raise CloudTemporaryError()
            except dropbox.stone_validators.ValidationError as e:
                log.debug("f*ed up api error: %s", e)
                if "never created" in str(e):
                    raise CloudFileNotFoundError()
                raise
            except requests.exceptions.ConnectionError as e:
                log.exception('api error handled exception %s:%s',
                              "dropbox", e.__class__.__name__)
                self.disconnect()
                raise CloudDisconnectedError()

    @property
    def root_id(self):
        if not self.__root_id:
            info = self.info_path("/")
            if not info and info.oid:
                raise CloudFileNotFoundError("Cannot read root")
            self.__root_id = info.oid
        return self.__root_id

    @property
    def sync_root_id(self):
        if not self.__sync_root_id:
            oid = None
            info = self.info_path(self.sync_root)
            if info:
                oid = info.oid
            if not oid:
                try:
                    oid = self.mkdir(self.sync_root)
                except (CloudFileNotFoundError, CloudFileExistsError):
                    raise CloudFileNotFoundError("Cannot create sync root")
            self.__sync_root_id = oid
        return self.__sync_root_id

    def disconnect(self):
        self.client = None

    @property
    def cursor(self):
        if not self.__cursor:
            res = self._api('files_list_folder_get_latest_cursor',
                            self.sync_root_id, recursive=True, include_deleted=True, limit=200)
            self.__cursor = res.cursor
        return self.__cursor

    def _events(self, cursor):
        for res in _FolderIterator(self._api, self.sync_root_id, recursive=True, cursor=cursor):
            exists = True

            log.debug("event %s", res)

            if isinstance(res, files.DeletedMetadata):
                # dropbox doesn't give you the id that was deleted
                # we need to get the ids of every revision
                # then find out which one was the latest before the deletion time
                # then get the oid for that

                revs = self._api('files_list_revisions',
                                 res.path_lower, limit=10)
                log.debug("revs %s", revs)
                deleted_time = revs.server_deleted
                latest_time = None
                for ent in revs.entries:
                    if ent.server_modified <= deleted_time and \
                            (latest_time is None or ent.server_modified >= latest_time):
                        oid = ent.id
                        latest_time = ent.server_modified
                if not oid:
                    log.error(
                        "skipping deletion %s, because we don't know the oid", res)
                    continue

                exists = False
                otype = None
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
            self.__cursor = res.cursor

    def events(self):      # pylint: disable=too-many-locals
        yield from self._events(self.cursor)

    def walk(self, since=None):
        yield from self._events(None)
        self.walked = True

    def listdir(self, oid) -> list:
        return list(self._listdir(oid, recursive=False))

    def _listdir(self, oid, *, recursive):
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
            yield DropboxInfo(otype, oid, ohash, path)

    def create(self, path, file_like, metadata=None):
        self._verify_parent_folder_exists(path)
        if self.exists_path(path):
            raise CloudFileExistsError(path)
        return self.upload(path, file_like, metadata)

    def upload(self, oid, file_like, metadata=None) -> 'OInfo':
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

        return OInfo(otype=FILE, oid=res.id, hash=res.content_hash, path=res.path_display)

    def download(self, oid, file_like):
        ok = self._api('files_download', oid)
        if not ok:
            raise CloudFileNotFoundError()
        res, content = ok
        for data in content.iter_content(self._upload_block_size):
            file_like.write(data)
        return OInfo(otype=FILE, oid=oid, hash=res.content_hash, path=res.path_display)

    def _attempt_rename_folder_over_empty_folder(self, info: OInfo, path):
        if info.otype != DIRECTORY:
            return False
        possible_conflict = self.info_path(path)
        if possible_conflict.otype == DIRECTORY:
            contents = self.listdir(possible_conflict.oid)
            if len(contents) > 0:
                raise CloudFileExistsError("Cannot rename over empty folder %s" % path)
            else:
                self.delete(possible_conflict.oid)
                self._api('files_move_v2', info.oid, path)
                return True
        else:
            if info.otype != possible_conflict.otype:
                raise CloudFileExistsError(path)

    def rename(self, oid, path):
        try:
            self._api('files_move_v2', oid, path)
        except CloudFileExistsError:
            info = self.info_oid(oid)
            if info.otype == DIRECTORY:
                success = self._attempt_rename_folder_over_empty_folder(info, path)
                if not success:
                    raise

    def mkdir(self, path, metadata=None) -> str:    # pylint: disable=arguments-differ, unused-argument
        self._verify_parent_folder_exists(path)
        if self.exists_path(path):
            info = self.info_path(path)
            if info.otype == FILE:
                raise CloudFileExistsError()
            else:
                log.debug("Skipped creating already existing folder: %s", path)
                return info.oid
        res = self._api('files_create_folder_v2', path)
        log.debug("dbx mkdir %s", res)
        res = res.metadata
        return res.id

    def delete(self, oid):
        try:
            self._api('files_delete_v2', oid)
        except CloudFileNotFoundError:
            return

    def exists_oid(self, oid) -> bool:
        return bool(self.info_oid(oid))

    def info_path(self, path) -> OInfo:
        try:
            log.debug("res info path %s", path)
            res = self._api('files_get_metadata', path)
            log.debug("res info path %s", res)

            oid = res.id
            if isinstance(res, files.FolderMetadata):
                otype = DIRECTORY
                fhash = None
            else:
                otype = FILE
                fhash = res.content_hash

            return DropboxInfo(otype, oid, fhash, path)
        except CloudFileNotFoundError:
            return None

    def exists_path(self, path) -> bool:
        return self.info_path(path) is not None

    def info_oid(self, oid) -> OInfo:
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

            return DropboxInfo(otype, oid, fhash, path)
        except CloudFileNotFoundError:
            return None

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
