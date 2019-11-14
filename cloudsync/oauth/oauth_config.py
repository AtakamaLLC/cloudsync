import logging
from typing import Optional, Tuple

from .redir_server import OAuthRedirServer

__all__ = ["OAuthConfig"]

log = logging.getLogger(__name__)

# this class delibarately not strict, since it can contain provider-specific configuration
# applications can derive from this class and provide appropriate defaults

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

        self.app_id = app_id
        self.app_secret = app_secret
        self.manual_mode = manual_mode
        self._redirect_server = redirect_server

        if self.manual_mode and self._redirect_server:
            raise ValueError('Cannot use both manual mode and an oauth server')

        if not self.manual_mode and not self._redirect_server:
            log.error("HERE!!! %s %s", host_name, port_range)
            self._redirect_server = OAuthRedirServer(html_generator=self._gen_html_response, 
                                                        port_range=port_range, host_name=host_name)

    def start_server(self, *, on_success, on_failure):
        self._redirect_server.run(on_success=on_success, on_failure=on_failure)

    def wait(self, timeout=None):
        self._redirect_server.wait(timeout=Timeout)

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
