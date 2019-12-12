import os
import io
import threading
import logging
from typing import Dict
from unittest.mock import patch

from cloudsync.providers import BoxProvider
from cloudsync.oauth import OAuthConfig, OAuthProviderInfo
from cloudsync.utils import is_subpath
from cloudsync.oauth.apiserver import ApiServer, ApiError, api_route

log = logging.getLogger(__name__)


class FakeBoxApi(ApiServer):
    def __init__(self):
        super().__init__("127.0.0.1", 0)
        self.upload_url = self.uri("/upload")
        self.calls: Dict[str, tuple] = {}

    @api_route("/users/me")
    def upload(self, ctx, req):
        self.called("users/me", (ctx, req))
        return {"id": "123"}

    @api_route("/token")
    def token(self, ctx, req):
        self.called("token", (ctx, req))
        return {
                "token_type": "bearer",
                "refresh_token": "r1",
                "access_token": "a1",
                "expires_in": 340,
                "scope": "yes",
                }

    @api_route(None)
    def default(self, ctx, req):
        meth = ctx.get("REQUEST_METHOD")
        uri = ctx.get("PATH_INFO")

        log.debug("api: %s, %s %s", meth, uri, req)
        return {}

    def called(self, name, args):
        log.debug("called %s", name)
        if name not in self.calls:
            self.calls[name] = []
        self.calls[name].append((name, args))

def fake_prov():
    # TODO: shutting this down is slow, fix that and then fix all tests using the api server to shut down, or use fixtures or something
    srv = FakeBoxApi()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base_url = srv.uri()
    
    class API(object):
        """Configuration object containing the URLs for the Box API."""
        BASE_API_URL = base_url.rstrip("/")
        UPLOAD_URL = base_url + "/upload"
        OAUTH2_API_URL = base_url + "oauth"
        OAUTH2_AUTHORIZE_URL = base_url + "oauth/auth"
        MAX_RETRY_ATTEMPTS = 1

    with patch("boxsdk.config.API", API) as api:
        prov = BoxProvider(OAuthConfig(app_id="fakeappid", app_secret="fakesecret"))
        prov._base_url = base_url
        prov._oauth_info = OAuthProviderInfo(
                auth_url=base_url + "auth",
                token_url=base_url + "token",
                scopes=['whatever'],
                )
        fake_creds = {
                "access_token": "BAZ",
                "refresh_token": "YO",
                }
        prov.connect(fake_creds)
        assert srv.calls["token"]
        assert srv.calls["quota"]
        return srv, prov
 
def test_upload():
    srv, prov = fake_prov()
    prov.large_file_size = 10
    prov.create("/small", io.BytesIO(b'123'))
    assert srv.calls["upload.put"]
    prov.create("/big", io.BytesIO(b'12345678901234567890'))
    assert srv.calls["upload.session"]
    assert srv.calls["upload"]

def test_mkdir():
    srv, prov = fake_prov()
    log.info("calls %s", list(srv.calls.keys()))
    prov.mkdir("/dir")
    assert srv.calls["mkdir"]

