import os
import threading
from unittest.mock import patch
import requests
import pytest

from cloudsync.oauth import OAuthConfig, OAuthError
from cloudsync.oauth.apiserver import ApiServer, api_route


class TokenServer(ApiServer):
    @api_route("/token")
    def token(ctx, req):
        return {
            "token_type": "bearer",
            "refresh_token": "r1",
            "access_token": "a1",
            "expires_in": 340
        }


@patch('webbrowser.open')
def test_oauth(wb):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    t = TokenServer("127.0.0.1", 0)
    threading.Thread(target=t.serve_forever, daemon=True).start()

    auth_url = t.uri("/auth")
    token_url = t.uri("/token")

    o = OAuthConfig(app_id="foo", app_secret="bar", port_range=(54045, 54099), host_name="localhost")
    o.start_auth(auth_url)
    wb.assert_called_once()
    requests.get(o.redirect_uri, params={"code": "cody"})
    res = o.wait_auth(token_url=token_url)

    assert res.refresh_token == "r1"
    assert res.expires_in == 340


@patch('webbrowser.open')
def test_oauth_interrupt(wb):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    t = TokenServer("127.0.0.1", 0)
    threading.Thread(target=t.serve_forever, daemon=True).start()

    auth_url = t.uri("/auth")
    token_url = t.uri("/token")

    o = OAuthConfig(app_id="foo", app_secret="bar", port_range=(54045, 54099), host_name="localhost")
    o.start_auth(auth_url)
    wb.assert_called_once()
    o.shutdown()
    with pytest.raises(OAuthError):
        res = o.wait_auth(token_url=token_url)
