"""
Fake api helpers for making mock provider apis
"""

import logging
import threading
from typing import Dict, List

from cloudsync.oauth.apiserver import ApiServer, ApiError, api_route
from cloudsync.oauth import OAuthProviderInfo, OAuthConfig

__all__ = ["FakeApi", "fake_oauth_provider", 'ApiError', 'api_route']

log = logging.getLogger(__name__)


class FakeApi(ApiServer):
    """
    Fake api base class, inherit from this.

        - spins up on init
        - default handler for all urls returns empty dict
        - logs all calls
    """

    def __init__(self):
        super().__init__("127.0.0.1", 0)
        self.calls: Dict[str, List] = {}
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @api_route("/token")
    def __token(self, ctx, req):
        self.called("token", (ctx, req))
        return {
                "token_type": "bearer",
                "refresh_token": "rtok",
                "access_token": "atok",
                "expires_in": 340,
                "scope": "yes",
                }

    @api_route(None)
    def __default(self, ctx, req):
        log.debug("url %s %s", ctx["REQUEST_METHOD"], ctx["PATH_INFO"])
        self.called("default", (ctx, req))
        return {}

    def called(self, name, args):
        """Call this to log calls to urls"""
        # todo, change to use mock call counts?
        log.debug("called %s", name)
        if name not in self.calls:
            self.calls[name] = []
        self.calls[name].append((name, args))


def fake_oauth_provider(api_server, provider_class):
    """
    Calling this returns an instance of the provider class with the oauth config set to the fake server.
    """
    # TODO: shutting this down is slow, fix that
    # and then make this a fixture
    srv = api_server
    base_url = srv.uri()

    prov = provider_class(OAuthConfig(app_id="fakeappid", app_secret="fakesecret"))
    prov._oauth_info = OAuthProviderInfo(
            auth_url=base_url + "auth",
            token_url=base_url + "token",
            scopes=['whatever'],
            )
    fake_creds = {
            "refresh_token": "rtok",
            "access_token": "atok",
            }
    prov.connect(fake_creds)
    return prov
