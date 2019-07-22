import logging
import threading

from ssl import SSLError
from apiclient.discovery import build   # pylint: disable=import-error
from apiclient.errors import HttpError  # pylint: disable=import-error
from httplib2 import Http, HttpLib2Error
from oauth2client import client         # pylint: disable=import-error
from oauth2client.client import HttpAccessTokenRefreshError # pylint: disable=import-error

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

    def get_quota(self, api_key=None, refresh_token=None):
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
        if api_key:
            res['api_key'] = api_key
        if refresh_token:
            res['refresh_token'] = refresh_token
        return res

    def connect(self, creds):
        log.debug('Connecting to googledrive')
        if not self.client:
            if not creds.get('api_key'):
                api_key = self.api_key
            if not creds.get('refresh_token'):
                refresh_token = self.refresh_token
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
                    self.get_quota(api_key=self.api_key,
                                   refresh_token=self.refresh_token)
                except SSLError:  # pragma: no cover
                    # Seeing some intermittent SSL failures that resolve on retry
                    log.warning('Retrying intermittent SSLError')
                    self.get_quota(api_key=self.api_key,
                                   refresh_token=self.refresh_token)
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
            except (TimeoutError, HttpLib2Error) as e:
                self.disconnect()
                raise CloudDisconnectedError("disconnected on timeout")

    def disconnect(self):
        self.client = None

    def events(self, timeout):
        ...

    def walk(self):
        ...

    def upload(self, oid, file_like):
        ...

    def create(self, path, file_like) -> 'ProviderInfo':
        ...

    def download(self, oid, file_like):
        ...

    def rename(self, oid, path):
        ...

    def mkdir(self, path) -> str:
        ...

    def delete(self, oid):
        ...

    def exists_oid(self, oid):
        ...

    def exists_path(self, path) -> bool:
        ...

    @staticmethod
    def hash_data(file_like):
        ...

    def remote_hash(self, oid):
        ...

    def info_path(self, path) -> ProviderInfo:
        ...

    def info_oid(self, oid) -> ProviderInfo:
        ...
