import os
import time
import arrow
import logging
import threading
import hashlib

from ssl import SSLError
from apiclient.discovery import build   # pylint: disable=import-error
from apiclient.errors import HttpError  # pylint: disable=import-error
from httplib2 import Http, HttpLib2Error
from oauth2client import client         # pylint: disable=import-error
from oauth2client.client import HttpAccessTokenRefreshError # pylint: disable=import-error

from apiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

from cloudsync import Provider, ProviderInfo
from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError, CloudFileNotFoundError, CloudTemporaryError

log = logging.getLogger(__name__)

class GDriveProvider(Provider):
    case_sensitive = False
    allow_renames_over_existing = False
    require_parent_folder = True

    _scope = "https://www.googleapis.com/auth/drive"
    _redir = 'urn:ietf:wg:oauth:2.0:oob'
    _token_uri = 'https://accounts.google.com/o/oauth2/token'

    def __init__(self):
        super().__init__()
        self.root_fileid = None
        self.flow = None
        self.client = None
        self.api_key = None
        self.refresh_token = None
        self.user_agent = 'cloudsync/1.0'
        self.mutex = threading.Lock()
        self._ids = {"/":"root"}

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

    def connect(self, creds={}):
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
                if str(e.resp.status) == '404':
                    raise CloudFileNotFoundError('File not found when executing %s.%s(%s)' % (
                        resource, method, kwargs
                    ))
                if (str(e.resp.status) == '403' and str(e.resp.reason) == 'Forbidden') or str(e.resp.status) == '429':
                    raise CloudTemporaryError("rate limit hit")
                
                raise CloudTemporaryError("unknown error")
            except (TimeoutError, HttpLib2Error) as e:
                self.disconnect()
                raise CloudDisconnectedError("disconnected on timeout")

    def disconnect(self):
        self.client = None

    def events(self, timeout):
        ...

    def walk(self):
        ...

    def upload(self, oid, file_like, metadata={}):
        gdrive_info = self.__prep_upload(None, file_like, metadata)

        ul = MediaIoBaseUpload(file_like, mimetype=gdrive_info.get('mimeType'), chunksize=4 * 1024 * 1024)

        fields = 'id, md5Checksum'

        res = self._api('files', 'update',
                body=gdrive_info,
                fileId=oid,
                media_body=ul,
                fields=fields)

        log.debug("response from upload %s", res)

        if not res:
            raise CloudTemporaryError("unknown response from drive on upload")

        return ProviderInfo(oid=res['id'], hash=res['md5Checksum'], path=None)

    def __prep_upload(self, path, file_like, metadata):
        # modification time
        mtime = metadata.get("modifiedTime", time.time())
        mtime = arrow.get(mtime).isoformat()
        gdrive_info = {
                'modifiedTime':  mtime
                }

        # mime type, if provided
        mime_type = metadata.get("mimeType", "application/octet-stream")
        if mime_type:
            gdrive_info['mimeType'] = mime_type

        # path, if provided
        if path:
            parent, name = os.path.split(path)
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

    def create(self, path, file_like, metadata={}) -> 'ProviderInfo':
        gdrive_info = self.__prep_upload(path, file_like, metadata)

        ul = MediaIoBaseUpload(file_like, mimetype=gdrive_info.get('mimeType'), chunksize=4 * 1024 * 1024)

        fields = 'id, md5Checksum'

        parent, name = os.path.split(path)
        if not self.exists_path(parent):
            raise CloudFileNotFoundError("parent folder %s doesn't exist", parent)
        parent_oid = self._ids[parent]

        gdrive_info['parents'] = [parent_oid]

        res = self._api('files', 'create',
                body=gdrive_info,
                media_body=ul,
                fields=fields)

        log.debug("response from upload %s", res)

        if not res:
            raise CloudTemporaryError("unknown response from drive on upload")

        self._ids[path] = res['id']

        return ProviderInfo(oid=res['id'], hash=res['md5Checksum'], path=path)

    def download(self, oid, file_like):
        req = self.client.files().get_media(fileId=oid)
        dl = MediaIoBaseDownload(file_like, req, chunksize=4 * 1024 * 1024)

        done = False
        while not done:
            try:
                status, done = dl.next_chunk()
            except HttpError as e:
                if str(e.resp.status) == '416':
                    log.debug("empty file downloaded")
                    done = True
                elif str(e.resp.status) == '404':
                    raise CloudFileNotFoundError("file %s not found", oid) 
                else:
                    raise CloudTemporaryError("unknown response from drive")
            except (TimeoutError, HttpLib2Error) as e:
                self.disconnect()
                raise CloudDisconnectedError("disconnected during download")

    def rename(self, oid, path):
        ...

    def mkdir(self, path) -> str:
        ...

    def delete(self, oid):
        ...

    def exists_oid(self, oid):
        ...

    def exists_path(self, path) -> bool:
        parent, name = os.path.split(path)
        if parent == "":
            parent = "/"

        if parent not in self._ids:
            if not exists_path(self, parent):
                return False
       
        if path in self._ids:
            return True

        parent_id = self._ids[parent]

        query = f"'{parent_id}' in parents and name='{name}'"

        res = self._api('files', 'list',
                q=query,
                spaces='drive',
                fields='files(id)',
                pageToken=None)

        if not res['files']:
            return False

        oid = res['files'][0]['id']

        self._ids[path] = oid

        return oid


    @staticmethod
    def hash_data(file_like):
        md5 = hashlib.md5()
        for c in iter(lambda: file_like.read(4096), b''):
            md5.update(c)
        retval = md5.hexdigest()
        return retval

    def remote_hash(self, oid):
        ...

    def info_path(self, path) -> ProviderInfo:
        ...

    def info_oid(self, oid) -> ProviderInfo:
        ...
