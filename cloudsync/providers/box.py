import threading
import logging

from typing import Optional, Generator

from boxsdk import OAuth2, Client
from cloudsync.utils import debug_args
from oauth2client.client import HttpAccessTokenRefreshError

from cloudsync.oauth import OAuthConfig

from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError
from cloudsync import Provider, OInfo, Hash, DirInfo, Cursor

log = logging.getLogger(__name__)
# logging.getLogger('googleapiclient').setLevel(logging.INFO)
# logging.getLogger('googleapiclient.discovery').setLevel(logging.WARN)
# ^ FIX THESE


class BoxProvider(Provider):
    def __init__(self, oauth_config: Optional[OAuthConfig] = None):
        super().__init__()

        self.client = None
        self.api_key = None
        self.refresh_token = None
        self.mutex = threading.Lock()

        # dont make this null maybe? raise a value exception
        self._oauth_config = oauth_config
        self._oauth_done = threading.Event()
        self._csrf_token = None

    def initialize(self):
        logging.error('initializing')
        if not self._oauth_config.manual_mode:
            try:
                logging.error('try auth')
                self._oauth_config.oauth_redir_server.run(
                    on_success=self._on_oauth_success,
                    on_failure=self._on_oauth_failure,
                )
                self._flow = OAuth2(client_id=self._oauth_config.app_id, client_secret=self._oauth_config.app_secret)
                url, self._csrf_token = self._flow.get_authorization_url(redirect_url=self._oauth_config.oauth_redir_server.uri('/auth/'))
                import webbrowser
                logging.error(self._oauth_config.oauth_redir_server.uri('/auth/'))
                webbrowser.open(url)
            except OSError:
                log.exception('Unable to use redir server. Falling back to manual mode')
                self._oauth_config.manual_mode = False

        self._oauth_done.clear()

    def interrupt_oauth(self):
        pass

    def _on_oauth_success(self, auth_dict):
        assert(self._csrf_token == auth_dict['state'][0]) # checks for csrf attack, what state am i in?
        try:
            self.api_key, self.refresh_token = self._flow.authenticate(auth_dict['code'])
            self._oauth_done.set()
        except Exception:
            log.exception('Authentication failed')
            raise

    def _on_oauth_failure(self, err):
        log.error("oauth failure: %s", err)
        self._oauth_done.set()

    def authenticate(self):
        logging.error('authenticating')
        try:
            self.initialize()
            self._oauth_done.wait()
            return {"refresh_token": self.refresh_token,
                    "api_key": self.api_key,
                    }
        finally:
            if not self._oauth_config.manual_mode:
                self._oauth_config.oauth_redir_server.shutdown()

    def get_quota(self):
        user = self.client.user(user_id='me').get()
        logging.error(dir(user))

        res = {
            'used': user.space_used,
            'total': user.space_amount,
            'login': user.login,
            'uid': user.id
        }
        logging.error(res)
        return res

    def connect(self, creds):
        log.debug('Connecting to box')
        if not self.client:
            api_key = creds.get('api_key', self.api_key)
            refresh_token = creds.get('refresh_token', self.api_key)
            self.__creds = creds

            if not refresh_token:
                raise CloudTokenError("acquire a token using authenticate() first")

            if (not self._oauth_config.app_id or not self._oauth_config.app_secret) and not api_key:
                raise CloudTokenError("require app_id/secret or api_key")
            # verify this ^ is proper for box

            try:
                with self.mutex:
                    self.client = Client(self._flow)

                if getattr(creds, 'refresh_token', None):
                    refresh_token = creds.refresh_token

            except HttpAccessTokenRefreshError:
                self.disconnect()
                raise CloudTokenError()
        return self.client

    def disconnect(self):
        self.client = None

    def _api(self, resource, method, *args, **kwargs):
        log.debug("_api: %s (%s)", method, debug_args(args, kwargs))

        with self.mutex:
            if not self.client:
                raise CloudDisconnectedError("currently disconnected")

            try:
                return getattr(self.client, method)(*args, **kwargs)
            except Exception as e:
                self.refresh_api_key()
                self.write_refresh_token_to_database()
                try:
                    return getattr(self.client, method)(*args, **kwargs)
                except Exception as e:
                    logging.error(e)

    @property
    def name(self):
        pass

    @property
    def latest_cursor(self):
        pass

    @property
    def current_cursor(self) -> Cursor:
        pass

    def events(self) -> Generator["Event", None, None]:
        pass

    def walk(self, path, since=None):
        pass

    def upload(self, oid, file_like, metadata=None) -> 'OInfo':
        pass

    def create(self, path, file_like, metadata=None) -> 'OInfo':
        pass

    def download(self, oid, file_like):
        pass

    def rename(self, oid, path) -> str:
        pass

    def mkdir(self, path) -> str:
        pass

    def delete(self, oid):
        pass

    def exists_oid(self, oid):
        pass

    def exists_path(self, path) -> bool:
        pass

    def listdir(self, oid) -> Generator[DirInfo, None, None]:
        pass

    def hash_data(self, file_like) -> Hash:
        pass

    def info_path(self, path: str) -> Optional[OInfo]:
        pass

    def info_oid(self, oid, use_cache=True) -> Optional[OInfo]:
        pass

    def get_parent_id(self, path):
        if not path:
            return None

        parent, _ = self.split(path)

        if parent == path:
            return self._ids.get(parent)

        # get the latest version of the parent path
        # it may have changed, or case may be different, etc.
        info = self.info_path(parent)
        if not info:
            raise CloudFileNotFoundError("parent %s must exist" % parent)

        # cache the latest version
        return self._ids[info.path]

    def refresh_api_key(self):
        # Use the refresh token to get a new api key and refresh token
        raise NotImplementedError

    def write_refresh_token_to_database(self):
        raise NotImplementedError
