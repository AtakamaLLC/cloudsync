import logging
from typing import Optional, Tuple
import webbrowser

from .redir_server import OAuthRedirServer
from requests_oauthlib import OAuth2Session

__all__ = ["OAuthConfig"]

# don't log tokens
logging.getLogger("requests_oauthlib").setLevel(logging.INFO)

log = logging.getLogger(__name__)

# this class delibarately not strict, since it can contain provider-specific configuration
# applications can derive from this class and provide appropriate defaults

class OAuthToken:
    def __init__(self, data):
        self.access_token = data["access_token"]
        self.token_type = data["token_type"]
        self.expires_in = data.get("expires_in")
        self.refresh_token = data.get("refresh_token")
        self.scope = data.get("scope")

class OAuthConfig:
    def __init__(self, *, app_id: str, app_secret: str, 
            manual_mode: bool = False, 
            redirect_server: Optional[OAuthRedirServer] = None, 
            port_range: Tuple[int, int] = None,
            host_name: str = None):
        """
        There are two ways to create an OAuthConfig object: by providing a OAuthRedirServer or by providing the
        success and failure callbacks, as well as the port and host configs
        :param app_id          
        :param app_secret          
        :param manual_mode          
        :param redirect_server (if none, one will be created for you)
        :param port_range (defaults to 'any port')
        :param host_name (defaults to 127.0.0.1)
        """

        # Ideally, provider-specific endpoints and behaviors are controlled by the provider code
        # Consumer-specific settings are initialized here
        # So far, only app id's and redir endpoints seem to be necessary

        self.app_id = app_id
        self.app_secret = app_secret
        self.manual_mode = manual_mode
        self.authorization_url = None
        
        self._redirect_server = redirect_server

        if manual_mode and self._redirect_server:
            raise ValueError('Cannot use both manual mode and an oauth server')

        if port_range and self._redirect_server:
            raise ValueError('If providing a server, no need to set port range')

        if not self.manual_mode and not self._redirect_server:
            self._redirect_server = OAuthRedirServer(html_generator=self._gen_html_response, 
                                                     port_range=port_range, host_name=host_name)


    def start_auth(self, auth_url, scope=None, **kwargs):
        self.start_server()
        self._session = OAuth2Session(client_id=self.app_id, scope=scope, redirect_uri=self.redirect_uri, **kwargs)
        self.authorization_url, state = self._session.authorization_url(auth_url)
        log.debug("start oauth url %s, redir %s, appid %s", self.authorization_url, self.redirect_uri, self.app_id)
        webbrowser.open(self.authorization_url)

    def wait_auth(self, token_url, **kwargs):
        self.wait_success()
        return OAuthToken(self._session.fetch_token(token_url,
                client_secret=self.app_secret,
                code=self.success_code,
                **kwargs))

    @property
    def success_code(self):
        return self._redirect_server.success_code

    @property
    def failure_info(self):
        return self._redirect_server.failure_info

    def start_server(self, *, on_success=None, on_failure=None):
        self._redirect_server.run(on_success=on_success, on_failure=on_failure)

    def wait_success(self, timeout=None):
        self._redirect_server.wait(timeout=timeout)

    def shutdown(self):
        self._redirect_server.shutdown()

    @property
    def redirect_uri(self) -> str:
        return self._redirect_server.uri()

    def _gen_html_response(self, success: bool, err_msg: str):
        if success:
            return self.success_message()
        else:
            return self.failure_message(err_msg)

    @staticmethod
    def success_message() -> str:
        return 'OAuth succeeded!'

    @staticmethod
    def failure_message(error_str: str) -> str:
        return 'OAuth failed: {}'.format(error_str)
