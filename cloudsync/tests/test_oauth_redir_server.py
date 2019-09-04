import logging
import requests
from unittest.mock import Mock
from cloudsync.oauth_redir_server import OAuthRedirServer
log = logging.getLogger(__name__)


def resp_gen(success: bool, error_msg: str) -> str:
    if success:
        return f'Success'
    else:
        return f'Failure: {error_msg}'


def test_oauth_redir_server():
    srv = OAuthRedirServer(resp_gen)
    def on_success(auth_dict):
        pass

    def on_failure(err_msg):
        pass

    on_success = Mock()

    srv.run(on_success=on_success, on_failure=on_failure, use_predefined_ports=False)
    port = srv._OAuthRedirServer__api_server.port()
    log.debug('>>>>>>>> Port is: %s', port)
    res = requests.get(url=f'http://127.0.0.1:{port}/auth/', params={
        'state': ['-T_wMR7edzQAc8i3UiH3Fg=='],
        'error_description': ['Long error descrption'],
        'error': ['badman']
    })
    assert res.status_code == 200
