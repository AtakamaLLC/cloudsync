import logging
import threading
import requests
from unittest.mock import Mock, patch
from cloudsync.apiserver import ApiServer
from cloudsync.oauth_redir_server import OAuthRedirServer
log = logging.getLogger(__name__)


def resp_gen(success: bool, error_msg: str) -> str:
    if success:
        return f'Success'
    else:
        return f'Failure: {error_msg}'


shutdown_signal = threading.Event()


class EventApiServer(ApiServer):
    def __init__(self, *args, **kwargs):
        # This signal ensures that the test function only starts shutting down the oauth server after the request is
        # received by the OAuth server
        super().__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        shutdown_signal.set()
        return super().__call__(*args, **kwargs)


@patch('cloudsync.oauth_redir_server.ApiServer', EventApiServer)
def test_oauth_redir_server():
    srv = OAuthRedirServer(resp_gen)
    on_success = Mock()
    on_failure = Mock()

    srv.run(on_success=on_success, on_failure=on_failure, use_predefined_ports=False)
    port = srv._OAuthRedirServer__api_server.port()

    def send_req():
        res = requests.get(url=f'http://127.0.0.1:{port}/auth/', params={
            'state': ['-T_wMR7edzQAc8i3UiH3Fg=='],
            'error_description': ['Long error descrption'],
            'error': ['badman']
        })
        assert res.status_code == 200

    t = threading.Thread(target=send_req)
    t.start()

    def patient_shutdown():
        shutdown_signal.wait()
        srv.shutdown()

    shutdown_threads = [threading.Thread(target=patient_shutdown) for i in range(1, 30)]

    # 11 threads all trying to shut down the save server at roughly the same time
    for st in shutdown_threads:
        st.start()
    shutdown_signal.wait()
    srv.shutdown()

    t.join(2)
    for st in shutdown_threads:
        st.join(2)

    on_success.assert_not_called()
    on_failure.assert_called_once()
