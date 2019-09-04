from cloudsync.oauth_redir_server import OAuthRedirServer


def resp_gen(success: bool, error_msg: str) -> str:
    if success:
        return f'Success'
    else:
        return f'Failure: {error_msg}'


@patch('cloudsync.oauth_redir_server')
def test_oauth_redir_server():
    srv = OAuthRedirServer(resp_gen)

    def on_success(auth_dict):
        pass

    def on_failure(err_msg):
        pass
