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
        return {'address': '',
                'avatar_url': 'https://app.box.com/api/avatar/large/8506151483',
                'created_at': '2019-05-29T08:35:19-07:00',
                'id': '8506151483',
                'job_title': '',
                'language': 'en',
                'login': 'AutomationUser_813890_GmcM3Cohcy@boxdevedition.com',
                'max_upload_size': 5368709120,
                'modified_at': '2019-12-12T05:13:29-08:00',
                'name': 'Atakama JWT',
                'notification_email': [],
                'phone': '',
                'space_amount': 10737418240,
                'space_used': 5551503,
                'status': 'active',
                'timezone': 'America/Los_Angeles',
                'type': 'user'}

    @api_route("/folders/*")
    def folders(self, ctx, req):
        self.called("token", (ctx, req))
        return {'content_created_at': None,
                'content_modified_at': None,
                'created_at': None,
                'created_by': {'id': '', 'login': '', 'name': '', 'type': 'user'},
                'description': '',
                'etag': None,
                'folder_upload_email': None,
                'id': '0',
                'item_collection':
                    {'entries':
                        [
                            {'etag': '0',
                                'id': '95401994626',
                                'name': '0109d27be3d76224f640e6076c77184d',
                                'sequence_id': '0',
                                'type': 'folder'},
                        ]}
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
        assert srv.calls["users/me"]
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

