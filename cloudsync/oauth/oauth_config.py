import logging
from typing import Optional

from .redir_server import OAuthRedirServer

__all__ = ["OAuthConfig"]

log = logging.getLogger(__name__)

# this class delibarately not strict, since it can contain provider-specific configuration
# applications can derive from this class and provide appropriate defaults

class OAuthConfig:
    def __init__(self, *, app_id: str = None, app_secret: str = None, manual_mode: bool = False, oauth_redir_server: Optional[OAuthRedirServer] = None):
        """
        There are two ways to create an OAuthConfig object: by providing a OAuthRedirServer or by providing the
        success and failure callbacks, as well as changing the `use_predefined_ports` parameter if desired.
        :param manual_mode:
        :param oauth_redir_server:
        """

        self.app_id = app_id
        self.app_secret = app_secret

        self.manual_mode = manual_mode
        self._oauth_redir_server = oauth_redir_server
        if self.manual_mode and self._oauth_redir_server:
            raise ValueError('Cannot use both manual mode and an oauth server')
        if not self.manual_mode and not self._oauth_redir_server:
            self._oauth_redir_server = OAuthRedirServer(html_generator=self._gen_html_response)

    @property
    def oauth_redir_server(self) -> Optional[OAuthRedirServer]:
        return self._oauth_redir_server

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
