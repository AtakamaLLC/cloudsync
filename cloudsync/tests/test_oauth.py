import os
import threading
from unittest.mock import patch
import requests
import pytest

from cloudsync.oauth import OAuthConfig, OAuthError, OAuthProviderInfo
from cloudsync.oauth.apiserver import ApiServer, api_route
from .fixtures import MockProvider

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
def test_oauth_refresh(wb):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    t = TokenServer("127.0.0.1", 0)
    threading.Thread(target=t.serve_forever, daemon=True).start()

    token_url = t.uri("/token")

    o = OAuthConfig(app_id="foo", app_secret="bar")
    res = o.refresh(token_url, "token", ["scope"])

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
        o.wait_auth(token_url=token_url)


@patch('webbrowser.open')
def test_oauth_defaults(wb):
    # this is not a very good test
    # really, the test instances are tested in the manual mode oauth tests
    # this is abstract-only testing mostly to explain what's going on

    # when CI testing, oauth providers stick tokens, ids, and secrets in the environment
    os.environ["TEST_APP_ID"] = "123"
    os.environ["TEST_APP_SECRET"] = "456"
    os.environ["TEST_TOKEN"] = "ABC|DEF"

    t = TokenServer("127.0.0.1", 0)
    threading.Thread(target=t.serve_forever, daemon=True).start()

    # here's an oauth provider
    class Prov(MockProvider):
        def __init__(self, oc: OAuthConfig):
            self.oauth_config = oc
        oauth_info = OAuthProviderInfo(             # signal's oauth mode
            auth_url=t.uri("/auth"),
            token_url=t.uri("/token"),
            scopes=[],
        )

    inst = Prov.oauth_test_instance(prefix="TEST")
    assert inst.oauth_config.app_id == "123"
    assert inst.oauth_config.app_secret == "456"
    assert inst.creds in [{"refresh_token": "ABC"}, {"refresh_token": "DEF"}]

    creds = None
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # this is a blocking function, set an event when creds are found
    event = threading.Event()

    def auth():
        nonlocal creds
        creds = inst.authenticate()
        event.set()
    threading.Thread(target=auth, daemon=True).start()

    while True:
        try:
            wb.assert_called_once()
            # pretend user clicked ok
            requests.get(inst.oauth_config.redirect_uri, params={"code": "cody"})
            break
        except AssertionError:
            # webbrowser not launched yet...
            pass

    # click received, wait for token
    event.wait()
    assert creds
