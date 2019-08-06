import time
import logging
import threading
from ssl import SSLError
import json
from typing import Generator, Optional

import arrow
from apiclient.discovery import build   # pylint: disable=import-error
from apiclient.errors import HttpError  # pylint: disable=import-error
from httplib2 import Http, HttpLib2Error
from oauth2client import client         # pylint: disable=import-error
from oauth2client.client import HttpAccessTokenRefreshError  # pylint: disable=import-error
from googleapiclient.http import _should_retry_response  # This is necessary because google masks errors

from apiclient.http import MediaIoBaseDownload, MediaIoBaseUpload  # pylint: disable=import-error

from cloudsync import Provider, OInfo, DIRECTORY, FILE, Event, DirInfo

from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError, CloudFileNotFoundError, CloudTemporaryError, CloudFileExistsError

log = logging.getLogger(__name__)


class GDriveInfo(DirInfo):              # pylint: disable=too-few-public-methods
    pids = []

    def __init__(self, *a, pids=None, **kws):
        super().__init__(*a, **kws)
        if pids is None:
            pids = []
        self.pids = pids


class GDriveProvider(Provider):         # pylint: disable=too-many-public-methods, too-many-instance-attributes
    case_sensitive = True
    require_parent_folder = True

    _scope = "https://www.googleapis.com/auth/drive"
    _redir = 'urn:ietf:wg:oauth:2.0:oob'
    _token_uri = 'https://accounts.google.com/o/oauth2/token'
    _folder_mime_type = 'application/vnd.google-apps.folder'
    _io_mime_type = 'application/octet-stream'

    def __init__(self):
        super().__init__()
        self.__root_id = None
        self.__cursor = None
        self.client = None
        self.api_key = None
        self.refresh_token = None
        self.user_agent = 'cloudsync/1.0'
        self.mutex = threading.Lock()
        self._ids = {"/": "root"}
        self._trashed_ids = {}

    @property
    def connected(self):
        return self.client is not None

    def get_quota(self):
        # https://developers.google.com/drive/api/v3/reference/about
        res = self._api('about', 'get', fields='storageQuota,user')

        quota = res['storageQuota']
        user = res['user']

        usage = int(quota['usage'])
        if 'limit' in quota and quota['limit']:
            limit = int(quota['limit'])
        else:
            # It is possible for an account to have unlimited space - pretend it's 1TB
            limit = 1024 * 1024 * 1024 * 1024

        res = {
            'used': usage,
            'total': limit,
            'login': user['emailAddress'],
            'uid': user['permissionId']
        }

        return res

    def connect(self, creds):
        log.debug('Connecting to googledrive')
        if not self.client:
            api_key = creds.get('api_key', self.api_key)
            refresh_token = creds.get('refresh_token', self.refresh_token)
            kwargs = {}
            try:
                with self.mutex:
                    creds = client.GoogleCredentials(access_token=api_key,
                                                     client_id=creds.get(
                                                         'client_id'),
                                                     client_secret=creds.get(
                                                         'client_secret'),
                                                     refresh_token=refresh_token,
                                                     token_expiry=None,
                                                     token_uri=self._token_uri,
                                                     user_agent=self.user_agent)
                    creds.refresh(Http())
                    self.client = build(
                        'drive', 'v3', http=creds.authorize(Http()))
                    kwargs['api_key'] = creds.access_token

                if getattr(creds, 'refresh_token', None):
                    refresh_token = creds.refresh_token

                self.refresh_token = refresh_token
                self.api_key = api_key

                try:
                    self.get_quota()
                except SSLError:  # pragma: no cover
                    # Seeing some intermittent SSL failures that resolve on retry
                    log.warning('Retrying intermittent SSLError')
                    self.get_quota()
            except HttpAccessTokenRefreshError:
                self.disconnect()
                raise CloudTokenError()

        return self.client

    def _api(self, resource, method, *args, **kwargs):          # pylint: disable=arguments-differ
        if not self.client:
            raise CloudDisconnectedError("currently disconnected")

        with self.mutex:
            try:
                res = getattr(self.client, resource)()
                meth = getattr(res, method)(*args, **kwargs)
                return meth.execute()
            except HttpAccessTokenRefreshError:
                self.disconnect()
                raise CloudTokenError()
            except HttpError as e:
                # gets a default something (actually the message, not the reason) using their secret interface
                reason = e._get_reason()  # pylint: disable=protected-access

                # parses the JSON of the content to get the reason from where it really lives in the content
                try:  # this code was copied from googleapiclient/http.py:_should_retry_response()
                    data = json.loads(e.content.decode('utf-8'))
                    if isinstance(data, dict):
                        reason = data['error']['errors'][0]['reason']
                    else:
                        reason = data[0]['error']['errors']['reason']
                except (UnicodeDecodeError, ValueError, KeyError):
                    log.warning('Invalid JSON content from response: %s', e.content)

                if str(e.resp.status) == '404':
                    raise CloudFileNotFoundError('File not found when executing %s.%s(%s)' % (
                        resource, method, kwargs
                    ))

                if str(e.resp.status) == '403' and str(reason) == 'parentNotAFolder':
                    raise CloudFileExistsError("Parent Not A Folder")

                if (str(e.resp.status) == '403' and reason in ('userRateLimitExceeded', 'rateLimitExceeded', )) or str(e.resp.status) == '429':
                    raise CloudTemporaryError("rate limit hit")

                # At this point, _should_retry_response() returns true for error codes >=500, 429, and 403 with
                #  the reason 'userRateLimitExceeded' or 'rateLimitExceeded'. 403 without content, or any other
                #  response is not retried. We have already taken care of some of those cases above, but we call this below
                #  to catch the rest, and in case they improve their library with more conditions. If we called
                #  meth.execute() above with a num_retries argument, all this retrying would happen in the google api
                #  library, and we wouldn't have to think about retries.
                should_retry = _should_retry_response(e.resp.status, e.content)
                if should_retry:
                    raise CloudTemporaryError("unknown error %s" % e)
                raise Exception("unknown error %s" % e)
            except (TimeoutError, HttpLib2Error):
                self.disconnect()
                raise CloudDisconnectedError("disconnected on timeout")

    @property
    def root_id(self):
        if not self.__root_id:
            res = self._api('files', 'get',
                            fileId='root',
                            fields='id',
                            )
            self.__root_id = res['id']
            self._ids['/'] = self.__root_id
        return self.__root_id

    def disconnect(self):
        self.client = None

    @property
    def cursor(self):
        if not self.__cursor:
            res = self._api('changes', 'getStartPageToken')
            self.__cursor = res.get('startPageToken')
        return self.__cursor

    def events(self):      # pylint: disable=too-many-locals
        page_token = self.cursor
        while page_token is not None:
            # log.debug("looking for events, timeout: %s", timeout)
            response = self._api('changes', 'list', pageToken=page_token, spaces='drive',
                                 includeRemoved=True, includeItemsFromAllDrives=True, supportsAllDrives=True)
            for change in response.get('changes'):
                log.debug("got event %s", change)

                # {'kind': 'drive#change', 'type': 'file', 'changeType': 'file', 'time': '2019-07-23T16:57:06.779Z',
                # 'removed': False, 'fileId': '1NCi2j1SjsPUTQTtaD2dFNsrt49J8TPDd', 'file': {'kind': 'drive#file',
                # 'id': '1NCi2j1SjsPUTQTtaD2dFNsrt49J8TPDd', 'name': 'dest', 'mimeType': 'application/octet-stream'}}

                # {'kind': 'drive#change', 'type': 'file', 'changeType': 'file', 'time': '2019-07-23T20:02:14.156Z',
                # 'removed': True, 'fileId': '1lhRe0nDplA6I5JS18642rg0KIbYN66lR'}

                ts = arrow.get(change.get('time')).float_timestamp
                oid = change.get('fileId')
                exists = not change.get('removed')

                fil = change.get('file')
                if fil:
                    if fil.get('mimeType') == self._folder_mime_type:
                        otype = DIRECTORY
                    else:
                        otype = FILE
                else:
                    otype = None

                ohash = None
                path = self._path_oid(oid)

                event = Event(otype, oid, path, ohash, exists, ts)

                log.debug("converted event %s as %s", change, event)

                yield event

            page_token = response.get('nextPageToken')
            if 'newStartPageToken' in response:
                self.__cursor = response.get('newStartPageToken')

    def _walk(self, oid):
        for ent in self.listdir(oid):
            event = Event(ent.otype, ent.oid, ent.path, None, True, time.time())
            log.debug("walk %s", event)
            yield event
            if ent.otype == DIRECTORY:
                if self.exists_oid(ent.oid):
                    yield from self._walk(ent.oid)

    def walk(self, path, since=None):
        info = self.info_path(path)
        if not info:
            raise CloudFileNotFoundError(path)
        yield from self._walk(info.oid)

    def __prep_upload(self, path, metadata):
        # modification time
        mtime = metadata.get("modifiedTime", time.time())
        mtime = arrow.get(mtime).isoformat()
        gdrive_info = {
            'modifiedTime':  mtime
        }

        # mime type, if provided
        mime_type = metadata.get("mimeType", None)
        if mime_type:
            gdrive_info['mimeType'] = mime_type

        # path, if provided
        if path:
            _, name = self.split(path)
            gdrive_info['name'] = name

        # misc properties, if provided
        app_props = metadata.get("appProperties", None)
        if app_props:
            # caller can specify google-specific stuff, if desired
            gdrive_info['appProperties'] = app_props

        # misc properties, if provided
        app_props = metadata.get("properties", None)
        if app_props:
            # caller can specify google-specific stuff, if desired
            gdrive_info['properties'] = app_props

        log.debug("info %s", gdrive_info)

        return gdrive_info

    def upload(self, oid, file_like, metadata=None) -> 'OInfo':
        if not metadata:
            metadata = {}
        gdrive_info = self.__prep_upload(None, metadata)

        ul = MediaIoBaseUpload(file_like, mimetype=self._io_mime_type, chunksize=4 * 1024 * 1024)

        fields = 'id, md5Checksum'

        res = self._api('files', 'update',
                        body=gdrive_info,
                        fileId=oid,
                        media_body=ul,
                        fields=fields)

        log.debug("response from upload %s", res)

        if not res:
            raise CloudTemporaryError("unknown response from drive on upload")

        md5 = res.get('md5Checksum', None)  # can be none if the user tries to upload to a folder
        if md5 is None:
            possible_conflict = self._info_oid(oid)
            if possible_conflict and possible_conflict.otype == DIRECTORY:
                raise CloudFileExistsError("Can only upload to a file: %s" % possible_conflict.path)
        return OInfo(otype=FILE, oid=res['id'], hash=md5, path=None)

    def create(self, path, file_like, metadata=None) -> 'OInfo':
        if not metadata:
            metadata = {}
        gdrive_info = self.__prep_upload(path, metadata)

        if self.exists_path(path):
            raise CloudFileExistsError()

        ul = MediaIoBaseUpload(file_like, mimetype=self._io_mime_type, chunksize=4 * 1024 * 1024)

        fields = 'id, md5Checksum'

        parent_oid = self.get_parent_id(path)

        gdrive_info['parents'] = [parent_oid]

        res = self._api('files', 'create',
                        body=gdrive_info,
                        media_body=ul,
                        fields=fields)

        log.debug("response from create %s : %s", path, res)

        if not res:
            raise CloudTemporaryError("unknown response from drive on upload")

        self._ids[path] = res['id']

        log.debug("path cache %s", self._ids)

        return OInfo(otype=FILE, oid=res['id'], hash=res['md5Checksum'], path=path)

    def download(self, oid, file_like):
        req = self.client.files().get_media(fileId=oid)
        dl = MediaIoBaseDownload(file_like, req, chunksize=4 * 1024 * 1024)

        done = False
        while not done:
            try:
                _, done = dl.next_chunk()
            except HttpError as e:
                if str(e.resp.status) == '416':
                    log.debug("empty file downloaded")
                    done = True
                elif str(e.resp.status) == '404':
                    raise CloudFileNotFoundError("file %s not found" % oid)
                else:
                    raise CloudTemporaryError("unknown response from drive")
            except (TimeoutError, HttpLib2Error):
                self.disconnect()
                raise CloudDisconnectedError("disconnected during download")

    def rename(self, oid, path):  # pylint: disable=too-many-locals
        pid = self.get_parent_id(path)

        add_pids = [pid]
        if pid == 'root':
            add_pids = [self.root_id]

        info = self._info_oid(oid)
        if info is None:
            raise CloudFileNotFoundError(oid)
        remove_pids = info.pids
        old_path = info.path

        _, name = self.split(path)
        body = {'name': name}

        if self.exists_path(path):
            possible_conflict = self.info_path(path)
            if FILE in (info.otype, possible_conflict.otype):
                raise CloudFileExistsError(path)
            # because of the preceding if, we know that the source and target must both be folders
            try:
                next(self.listdir(possible_conflict.oid))
                raise CloudFileExistsError("Cannot rename over non-empty folder %s" % path)
            except StopIteration:
                pass  # Folder is empty, rename over it no problem
            self.delete(possible_conflict.oid)

        if not old_path:
            for cpath, coid in list(self._ids.items()):
                if coid == oid:
                    old_path = cpath

        if not old_path:
            old_path = self._path_oid(oid)

        self._api('files', 'update', body=body, fileId=oid, addParents=add_pids, removeParents=remove_pids, fields='id')

        for cpath, coid in list(self._ids.items()):
            if self.is_subpath(old_path, cpath):
                new_cpath = self.replace_path(cpath, old_path, path)
                self._ids.pop(cpath)
                self._ids[new_cpath] = oid

        log.debug("renamed %s", body)

    def listdir(self, oid) -> Generator[GDriveInfo, None, None]:
        query = f"'{oid}' in parents"
        try:
            res = self._api('files', 'list',
                            q=query,
                            spaces='drive',
                            fields='files(id, md5Checksum, parents, name, mimeType, trashed)',
                            pageToken=None)
        except CloudFileNotFoundError:
            if self._info_oid(oid):
                return
            log.debug("listdir oid gone %s", oid)
            raise

        if not res or not res['files']:
            if self.exists_oid(oid):
                return
            raise CloudFileNotFoundError(oid)

        log.debug("listdir got res %s", res)

        for ent in res['files']:
            fid = ent['id']
            pids = ent['parents']
            fhash = ent.get('md5Checksum')
            name = ent['name']
            trashed = ent.get('trashed', False)
            if ent.get('mimeType') == self._folder_mime_type:
                otype = DIRECTORY
            else:
                otype = FILE
            if not trashed:
                yield GDriveInfo(otype, fid, fhash, None, pids=pids, name=name)

    def mkdir(self, path, metadata=None) -> str:    # pylint: disable=arguments-differ
        if self.exists_path(path):
            info = self.info_path(path)
            if info.otype == FILE:
                raise CloudFileExistsError(path)
            log.debug("Skipped creating already existing folder: %s", path)
            return info.oid
        pid = self.get_parent_id(path)
        _, name = self.split(path)
        file_metadata = {
            'name': name,
            'parents': [pid],
            'mimeType': self._folder_mime_type,
        }
        if metadata:
            file_metadata.update(metadata)
        res = self._api('files', 'create',
                        body=file_metadata, fields='id')
        fileid = res.get('id')
        self._ids[path] = fileid
        return fileid

    def delete(self, oid):
        info = self.info_oid(oid)
        if not info:
            log.debug("deleted non-existing oid %s", oid)
            return  # file doesn't exist already...
        if info.otype == DIRECTORY:
            try:
                next(self.listdir(oid))
                raise CloudFileExistsError("Cannot delete non-empty folder %s:%s" % (oid, info.path))
            except StopIteration:
                pass  # Folder is empty, delete it no problem
        try:
            self._api('files', 'delete', fileId=oid)
        except CloudFileNotFoundError:
            log.debug("deleted non-existing oid %s", oid)
        for currpath, curroid in list(self._ids.items()):
            if curroid == oid:
                self._trashed_ids[currpath] = self._ids[currpath]
                del self._ids[currpath]

    def exists_oid(self, oid):
        return self._info_oid(oid) is not None

    def info_path(self, path) -> OInfo:
        if path == "/":
            return self.info_oid(self.root_id)

        try:
            parent_id = self.get_parent_id(path)
            _, name = self.split(path)

            query = f"'{parent_id}' in parents and name='{name}'"

            res = self._api('files', 'list',
                            q=query,
                            spaces='drive',
                            fields='files(id, md5Checksum, parents, mimeType)',
                            pageToken=None)
        except CloudFileNotFoundError:
            return None

        if not res['files']:
            return None

        ent = res['files'][0]

        log.debug("res is %s", res)

        oid = ent['id']
        pids = ent['parents']
        fhash = ent.get('md5Checksum')
        if ent.get('mimeType') == self._folder_mime_type:
            otype = DIRECTORY
        else:
            otype = FILE

        self._ids[path] = oid

        return GDriveInfo(otype, oid, fhash, path, pids=pids)

    def exists_path(self, path) -> bool:
        if path in self._ids:
            return True
        return self.info_path(path) is not None

    def get_parent_id(self, path):
        if not path:
            return None

        parent, _ = self.split(path)

        if parent == path:
            return self._ids.get(parent)

        if not self.exists_path(parent):
            raise CloudFileNotFoundError("parent %s must exist" % parent)

        return self._ids[parent]

    def _path_oid(self, oid, info=None) -> str:
        "convert oid to path"
        for p, pid in self._ids.items():
            if pid == oid:
                return p

        for p, pid in self._trashed_ids.items():
            if pid == oid:
                return p

        # todo, better cache, keep up to date, etc.

        if not info:
            info = self._info_oid(oid)

        if info and info.pids and info.name:
            ppath = self._path_oid(info.pids[0])
            if ppath:
                path = self.join(ppath, info.name)
                self._ids[path] = oid
                return path
        return None

    def info_oid(self, oid) -> OInfo:
        info = self._info_oid(oid)
        if info is None:
            return None
        # expensive
        path = self._path_oid(oid, info)
        ret = OInfo(info.otype, info.oid, info.hash, path)
        log.debug("info oid ret: %s", ret)
        return ret

    def _info_oid(self, oid) -> Optional[GDriveInfo]:
        try:
            res = self._api('files', 'get', fileId=oid,
                            fields='name, md5Checksum, parents, mimeType',
                            )
        except CloudFileNotFoundError:
            return None

        log.debug("info oid %s", res)

        pids = res.get('parents')
        fhash = res.get('md5Checksum')
        name = res.get('name')
        if res.get('mimeType') == self._folder_mime_type:
            otype = DIRECTORY
        else:
            otype = FILE

        return GDriveInfo(otype, oid, fhash, None, pids=pids, name=name)
