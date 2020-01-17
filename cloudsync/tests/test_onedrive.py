import os
import io
import threading
import logging
from unittest.mock import patch
import re

import pytest

from onedrivesdk_fork.error import ErrorCode
from cloudsync.providers import OneDriveProvider
from cloudsync.exceptions import CloudNamespaceError, CloudDisconnectedError, CloudTokenError
from cloudsync.oauth import OAuthConfig, OAuthProviderInfo
from cloudsync.oauth.apiserver import ApiServer, ApiError, api_route
from .fixtures import FakeApi, fake_oauth_provider

log = logging.getLogger(__name__)


class FakeGraphApi(FakeApi):
    @api_route("/upload")
    def upload(self, ctx, req):
        self.called("upload", (ctx, req))
        return {"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#drives('bdd46067213df13')/items/$entity","@microsoft.graph.downloadUrl":"https://mckvog.bn.files.1drv.com/y4pxeIYeQKLFVu82R-paaa0e99SXlcC2zAz7ipLsi9EKUPVVsjUe-YBY2tXL6Uwr1KX4HP0tvg3kKejnhtmn79J8i6TW0-wYpdNvNCAKxAVi6UiBtIOUVtd75ZelLNsT_MpNzn65PdB5l926mUuPHq4Jqv3_FKdZCr0LmHm_QbbdEFenK3WgvDwFKIZDWCXEAdYxdJPqd2_wk0LVU9ClY4XBIcw84WPA1KdJbABz93ujiA","createdDateTime":"2019-12-04T15:24:18.523Z","cTag":"aYzpCREQ0NjA2NzIxM0RGMTMhMTAxMi4yNTc","eTag":"aQkRENDYwNjcyMTNERjEzITEwMTIuMQ","id":"BDD46067213DF13!1012","lastModifiedDateTime":"2019-12-04T15:24:19.717Z","name":"d943ae092dbf377dd443a9579eb10898.dest","size":32,"webUrl":"https://1drv.ms/u/s!ABPfE3IGRt0Lh3Q","createdBy":{"application":{"displayName":"Atakama","id":"4423e6ce"},"user":{"displayName":"Atakama --","id":"bdd46067213df13"}},"lastModifiedBy":{"application":{"displayName":"Atakama","id":"4423e6ce"},"user":{"displayName":"Atakama --","id":"bdd46067213df13"}},"parentReference":{"driveId":"bdd46067213df13","driveType":"personal","id":"BDD46067213DF13!1011","name":"3676c7b907d09b2d9681084a47bcae59","path":"/drive/root:/3676c7b907d09b2d9681084a47bcae59"},"file":{"mimeType":"application/octet-stream","hashes":{"quickXorHash":"MO4Q2k+0wIrVLvPvyFNEXjENmJU=","sha1Hash":"9B628BE5312D2F5E7B6ADB1D0114BC49595269BE"}},"fileSystemInfo":{"createdDateTime":"2019-12-04T15:24:18.523Z","lastModifiedDateTime":"2019-12-04T15:24:19.716Z"}}

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

    @api_route("/me/drive")
    def me_drive(self, ctx, req):
        self.called("quota", (ctx, req))
        return {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#drives/$entity', 'id': 'bdd46067213df13', 'driveType': 'personal', 'owner': {'user': {'displayName': 'Atakama --', 'id': 'bdd46067213df13'}}, 'quota': {'deleted': 15735784, 'remaining': 1104878763593, 'state': 'normal', 'total': 1104880336896, 'used': 1573303}}

    @api_route("/drives/")
    def default(self, ctx, req):
        upload_url = self.uri("/upload")
        meth = ctx.get("REQUEST_METHOD")
        uri = ctx.get("PATH_INFO")

        if meth == "GET":
            self.called("get", (uri,))
            log.debug("getting")
            if re.match(r"^/drives/[^/]+/$", uri):
                return {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#drives/$entity', 'id': 'bdd46067213df13', 'driveType': 'personal', 'owner': {'user': {'displayName': 'Atakama --', 'id': 'bdd46067213df13'}}, 'quota': {'deleted': 519205504, 'remaining': 1104878758982, 'state': 'normal', 'total': 1104880336896, 'used': 1577914}}

            err = ApiError(404, json={"error": {"code": ErrorCode.ItemNotFound, "message": "whatever"}}) 
            log.debug("raising %s", err)
            raise err

        if meth == "POST" and "/createUploadSession" in uri:
            self.called("upload.session", (uri,))
            log.debug("upload")
            return {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#microsoft.graph.uploadSession', 'expirationDateTime': '2019-12-11T15:32:31.101Z', 'nextExpectedRanges': ['0-'], 'uploadUrl': upload_url}

        if meth == "PUT":
            self.called("upload.put", (uri,))
            return {"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#drives('bdd46067213df13')/items/$entity", "@microsoft.graph.downloadUrl":"https://mckvog.bn.files.1drv.com/y4pxeIYeQKLFVu82R-paaa0e99SXlcC2zAz7ipLsi9EKUPVVsjUe-YBY2tXL6Uwr1KX4HP0tvg3kKejnhtmn79J8i6TW0-wYpdNvNCAKxAVi6UiBtIOUVtd75ZelLNsT_MpNzn65PdB5l926mUuPHq4Jqv3_FKdZCr0LmHm_QbbdEFenK3WgvDwFKIZDWCXEAdYxdJPqd2_wk0LVU9ClY4XBIcw84WPA1KdJbABz93ujiA", "createdDateTime":"2019-12-04T15:24:18.523Z", "cTag":"aYzpCREQ0NjA2NzIxM0RGMTMhMTAxMi4yNTc", "eTag":"aQkRENDYwNjcyMTNERjEzITEwMTIuMQ", "id":"BDD46067213DF13!1012", "lastModifiedDateTime":"2019-12-04T15:24:19.717Z", "name":"d943ae092dbf377dd443a9579eb10898.dest", "size":32, "webUrl":"https://1drv.ms/u/s!ABPfE3IGRt0Lh3Q", "createdBy":{"application":{"displayName":"Atakama", "id":"4423e6ce"}, "user":{"displayName":"Atakama --", "id":"bdd46067213df13"}}, "lastModifiedBy":{"application":{"displayName":"Atakama", "id":"4423e6ce"}, "user":{"displayName":"Atakama --", "id":"bdd46067213df13"}}, "parentReference":{"driveId":"bdd46067213df13", "driveType":"personal", "id":"BDD46067213DF13!1011", "name":"3676c7b907d09b2d9681084a47bcae59", "path":"/drive/root:/3676c7b907d09b2d9681084a47bcae59"}, "file":{"mimeType":"application/octet-stream", "hashes":{"quickXorHash":"MO4Q2k+0wIrVLvPvyFNEXjENmJU=", "sha1Hash":"9B628BE5312D2F5E7B6ADB1D0114BC49595269BE"}}, "fileSystemInfo":{"createdDateTime":"2019-12-04T15:24:18.523Z", "lastModifiedDateTime":"2019-12-04T15:24:19.716Z"}}

        if meth == "POST" and "/children" in uri:
            self.called("mkdir", (uri,))
            return {'something': 'here'}

        log.debug("api: %s, %s %s", meth, uri, req)
        return {}


def fake_odp():
    # TODO: shutting this down is slow, fix that and then fix all tests using the api server to shut down, or use fixtures or something
    srv = FakeGraphApi()

    base_url = srv.uri()
    with patch.object(OneDriveProvider, "_base_url", base_url):
        prov = fake_oauth_provider(srv, OneDriveProvider)
        assert srv.calls["token"]
        assert srv.calls["quota"]
        return srv, prov


def test_upload():
    srv, odp = fake_odp()
    odp.create("/small", io.BytesIO())
    assert srv.calls["upload.put"]
    odp.create("/big", io.BytesIO(b'12345678901234567890'))
    assert srv.calls["upload.session"]
    assert srv.calls["upload"]


def test_mkdir():
    srv, odp = fake_odp()
    log.info("calls %s", list(srv.calls.keys()))
    odp.mkdir("/dir")
    assert srv.calls["mkdir"]


def test_root_event():
    srv, odp = fake_odp()
    root_event = {'@odata.type': '#microsoft.graph.driveItem', 'createdDateTime': '2019-10-27T05:46:04Z', 'id': '01LYWINUF6Y2GOVW7725BZO354PWSELRRZ', 'lastModifiedDateTime': '2020-01-02T15:45:55Z', 'name': 'root', 'webUrl': 'https://vidaid-my.sharepoint.com/personal/jack_vidaid_onmicrosoft_com/Documents', 'size': 6642351, 'parentReference': {'driveId': 'root', 'driveType': 'business'}, 'fileSystemInfo': {'createdDateTime': '2019-10-27T05:46:04Z', 'lastModifiedDateTime': '2020-01-02T15:45:55Z'}, 'folder': {'childCount': 5}, 'root': {}}
    non_root_event = {'@odata.type': '#microsoft.graph.driveItem', 'createdDateTime': '2020-01-02T15:44:44Z', 'eTag': '"{F0D504AA-C7E0-4B49-B529-63DEB72E09FE},1"', 'id': '01LYWINUFKATK7BYGHJFF3KKLD323S4CP6', 'lastModifiedDateTime': '2020-01-02T15:44:44Z', 'name': '20200102-02', 'webUrl': 'https://vidaid-my.sharepoint.com/personal/jack_vidaid_onmicrosoft_com/Documents/20200102-02', 'cTag': '"c:{F0D504AA-C7E0-4B49-B529-63DEB72E09FE},0"', 'size': 0, 'createdBy': {'application': {'displayName': 'Atakama'}, 'user': {'email': 'jack@vidaid.onmicrosoft.com', 'displayName': 'jack'}}, 'parentReference': {'driveId': 'root', 'driveType': 'business', 'id': '01LYWINUF6Y2GOVW7725BZO354PWSELRRZ', 'path': '/drive/root:'}, 'fileSystemInfo': {'createdDateTime': '2020-01-02T15:44:44Z', 'lastModifiedDateTime': '2020-01-02T15:44:44Z'}, 'folder': {'childCount': 2}}

    assert odp._convert_to_event(root_event, "123") is None
    assert odp._convert_to_event(non_root_event, "123") is not None


def test_namespace_get():
    srv, odp = fake_odp()
    ns = odp.namespace
    nsid = odp.namespace_id
    assert ns
    assert nsid

def test_namespace_set():
    srv, odp = fake_odp()
    odp.namespace = "personal"
    nsid = odp.namespace_id
    assert nsid

def test_namespace_set_err():
    srv, odp = fake_odp()
    with pytest.raises(CloudNamespaceError):
        odp.namespace = "bad-namespace"

def test_namespace_set_disconn():
    srv, odp = fake_odp()
    odp.disconnect()
    with pytest.raises(CloudDisconnectedError):
        odp.namespace = "whatever"

def test_namespace_set_other():
    srv, odp = fake_odp()

    def raise_error():
        raise CloudTokenError("yo")

    with patch.object(odp, '_direct_api', side_effect=raise_error):
        with pytest.raises(CloudTokenError):
            odp.namespace = "whatever"

