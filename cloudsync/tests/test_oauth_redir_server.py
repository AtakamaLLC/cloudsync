import logging
import time
import threading
import requests
from unittest.mock import Mock, patch

from cloudsync.oauth import OAuthRedirServer
from cloudsync.oauth.apiserver import ApiServer
from cloudsync.tests import RunUntilHelper

log = logging.getLogger(__name__)

def resp_gen(success: bool, error_msg: str) -> str:
    time.sleep(2)  # We are making a biiiiiig response that takes way too long
    if success:
        return f'Success'
    else:
        return f'Failure: {error_msg}'


shutdown_signal = threading.Event()
server_close_calls = 0


class EventApiServer(ApiServer):
    def __init__(self, *args, **kwargs):
        # This signal ensures that the test function only starts shutting down the oauth server after the request is
        # received by the OAuth server
        super().__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        shutdown_signal.set()
        return super().__call__(*args, **kwargs)

    def server_close(self):
        global server_close_calls
        server_close_calls += 1
        super().server_close()


@patch('cloudsync.oauth.redir_server.ApiServer', EventApiServer)
def test_oauth_redir_server():
    srv = OAuthRedirServer(html_generator=resp_gen)
    on_success = Mock()
    on_failure = Mock()

    global server_close_calls
    server_close_calls = 0

    # should have no effect on server that is not yet running
    srv.server_close()
    assert server_close_calls == 0

    srv.run(on_success=on_success, on_failure=on_failure)
    port = srv.port()

    # should have no effect on server that is running but has not been shutdown yet
    srv.server_close()
    assert server_close_calls == 0

    def send_req():
        res = requests.get(url=f'http://127.0.0.1:{port}/auth/', params={
            'state': ['-T_wMR7edzQAc8i3UiH3Fg=='],
            'error_description': ['Long error descrption'],
            'error': ['badman']
        })
        assert res.status_code == 200

    t = threading.Thread(target=send_req, daemon=True)
    t.start()

    shutdown_signal.wait()
    srv.shutdown()
    srv.server_close()
    assert server_close_calls == 1

    t.join(4)
    assert not t.is_alive()

    on_success.assert_not_called()
    on_failure.assert_called_once()


def test_server_close():
    api = ApiServer("127.0.0.1", 0)
    with patch.object(api, "_ApiServer__server") as server:
        # not started yet
        api.server_close()
        server.server_close.assert_not_called()

        # started, but not shutdown yet
        t = threading.Thread(target=api.serve_forever, daemon=True)
        t.start()
        RunUntilHelper.wait_until(lambda: api._ApiServer__started)  # type: ignore
        api.server_close()
        server.server_close.assert_not_called()

        # started and shutdown
        api.shutdown()
        api.server_close()
        server.server_close.assert_called_once()
