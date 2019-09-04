from typing import Optional, Callable
from .oauth_redir_server import OAuthRedirServer


class OAuthConfig:
    """
    - Oauth server, Optional
    - Manual mode bool property
    - Success/fail message functions
    """

    def __init__(self,
                 on_success: Callable[[dict], None],
                 manual_mode: bool = False,
                 oauth_redir_server: Optional[OAuthRedirServer] = None,
                 use_predefined_ports: bool = False,
                 on_failure: Callable = None):

        self.manual_mode = manual_mode
        self._oauth_redir_server = oauth_redir_server
        if not self.manual_mode and not self._oauth_redir_server:
            self._oauth_redir_server = OAuthRedirServer(on_success,
                                                        use_predefined_ports=use_predefined_ports,
                                                        on_failure=on_failure,
                                                        html_response_generator=self._gen_html_response)

    @property
    def oauth_redir_server(self) -> OAuthRedirServer:
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
