import os
import logging
from typing import Optional, Tuple, Any
import webbrowser
from oauthlib.oauth2 import OAuth2Error
from requests_oauthlib import OAuth2Session

from .redir_server import OAuthRedirServer

__all__ = ["OAuthConfig", "OAuthToken", "OAuthError"]

# don't log tokens
logging.getLogger("requests_oauthlib").setLevel(logging.INFO)

log = logging.getLogger(__name__)

OAuthError = OAuth2Error

# this class delibarately not strict, since it can contain provider-specific configuration
# applications can derive from this class and provide appropriate defaults


class OAuthToken:       # pylint: disable=too-few-public-methods
    """
    Just a class representation of the oauth2 standard token.

    See: https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
    """
    def __init__(self, data=None, **kwargs):
        if data is None:
            data = kwargs
        self.access_token = data["access_token"]
        self.token_type = data["token_type"]
        self.expires_in = data.get("expires_in")
        self.refresh_token = data.get("refresh_token")
        self.scope = data.get("scope")


class OAuthConfig:
    """
    Required argument for providers that return True to uses_oauth.

    Args:
        app_id: also known as "client id", provided for your application by the cloud provider
        app_secret: also known as "client secret", provided for your application by the cloud provider
        manual_mode: set to True, if you don't intend to use the redirect server
        redirect_server: a server that, at a minimum, supports the uri() command, probably should just change this to uri()
        port_range: the range of valid ports for your registered app (some providers burden you with this)
        host_name: defaults to 127.0.0.1
    """
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
        self._session: OAuth2Session = None
        self._token: OAuthToken = None

        self._redirect_server = redirect_server

        if manual_mode and self._redirect_server:
            raise ValueError('Cannot use both manual mode and an oauth server')

        if port_range and self._redirect_server:
            raise ValueError('If providing a server, no need to set port range')

        if not self.manual_mode and not self._redirect_server:
            self._redirect_server = OAuthRedirServer(html_generator=self._gen_html_response,
                                                     port_range=port_range, host_name=host_name)

    def start_auth(self, auth_url, scope=None, **kwargs):
        """
        Call this if you want oauth to be handled for you
        This starts a server, pops a browser.
        Do some stuff, then follow with wait_auth() to wait
        """
        log.debug("appid %s", self.app_id)
        if self.app_id is None:
            raise OAuthError("app id None")
        if self.app_secret is None:
            raise OAuthError("app secret is None")
        if auth_url is None:
            raise OAuthError("auth url bad")
        os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
        self.start_server()
        self._session = OAuth2Session(client_id=self.app_id, scope=scope, redirect_uri=self.redirect_uri, **kwargs)
        self.authorization_url, _unused_state = self._session.authorization_url(auth_url)
        log.debug("start oauth url %s, redir %s, appid %s", self.authorization_url, self.redirect_uri, self.app_id)
        webbrowser.open(self.authorization_url)

    def wait_auth(self, token_url, timeout=None, **kwargs):
        """
        Returns an OAuthToken object, or raises a OAuthError
        """
        assert self._session
        try:
            if not self.wait_success(timeout):
                if self.failure_info:
                    raise OAuthError(self.failure_info)
                raise OAuthError("Oauth interrupted")

            self._token = OAuthToken(self._session.fetch_token(token_url,
                                     include_client_id=True,
                                     client_secret=self.app_secret,
                                     code=self.success_code,
                                     timeout=60,
                                     **kwargs))
            self._token_changed()
            return self._token
        finally:
            self.shutdown()

    def refresh(self, refresh_url, token=None, scope=None, **extra):
        """
        Given a refresh url (often the same as token_url), will refresh the token
        Call this when your provider raises an exception implying your token has expired
        Or, you could just call it before the expiration
        """
        assert self._session or scope
        if not self._session and scope:
            self._session = OAuth2Session(client_id=self.app_id, scope=scope, redirect_uri=self.redirect_uri)
        extra["client_id"] = self.app_id
        extra["client_secret"] = self.app_secret
        extra["timeout"] = 60
        if isinstance(token, OAuthToken):
            token = token.refresh_token
        self._token = OAuthToken(self._session.refresh_token(refresh_url, refresh_token=token, **extra))
        if self._token.refresh_token != token:
            self._token_changed()
        return self._token

    @property
    def success_code(self):
        return self._redirect_server.success_code

    @property
    def failure_info(self):
        return self._redirect_server.failure_info

    def start_server(self, *, on_success=None, on_failure=None):
        """
        Start the redirect server in a thread
        """
        assert self._redirect_server
        self._redirect_server.run(on_success=on_success, on_failure=on_failure)

    def wait_success(self, timeout=None):
        """
        Wait for the redirect server, return true if it succeeded
        Shut down the server
        """
        assert self._redirect_server
        try:
            self._redirect_server.wait(timeout=timeout)
            return bool(self._redirect_server.success_code)
        finally:
            self.shutdown()

    def shutdown(self):
        """
        Stop the redirect server, and interrupt/fail any ongoing oauth
        """
        assert self._redirect_server
        self._redirect_server.shutdown()

    @property
    def redirect_uri(self) -> str:
        """
        Get the redirect server's uri
        """
        if self._redirect_server is None:
            return None
        return self._redirect_server.uri()

    def _gen_html_response(self, success: bool, err_msg: str):
        if success:
            return self.success_message()
        else:
            return self.failure_message(err_msg)

    def _token_changed(self):
        # this could just be a setter
        creds = {"refresh_token": self._token.refresh_token, "access_token": self._token.access_token}
        self.creds_changed(creds)

    def creds_changed(self, creds: Any):     # pylint: disable=unused-argument, no-self-use
        """Override this to save creds on refresh"""
        log.warning("creds will not be saved, implement OAuthConfig.creds_changed to save it.")

    # override this to make a nicer message on success
    @staticmethod
    def success_message() -> str:
        return 'OAuth succeeded!'

    # override this to make a nicer message on failure
    @staticmethod
    def failure_message(error_str: str) -> str:
        return 'OAuth failed: {}'.format(error_str)
