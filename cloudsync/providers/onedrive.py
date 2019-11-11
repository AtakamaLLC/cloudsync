# https://dev.onedrive.com/
# https://docs.microsoft.com/en-us/onedrive/developer/rest-api/concepts/upload?view=odsp-graph-online
# https://github.com/OneDrive/onedrive-sdk-python
# https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/msa-oauth?view=odsp-graph-online
# https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/app-registration?view=odsp-graph-online
import time
import logging
from pprint import pformat
import threading
import asyncio
import hashlib
import json
from typing import Generator, Optional, List, Dict, Any
import urllib.parse
import requests

import arrow
# from googleapiclient.discovery import build   # pylint: disable=import-error
# from googleapiclient.errors import HttpError  # pylint: disable=import-error
# from httplib2 import Http, HttpLib2Error
# from oauth2client import client         # pylint: disable=import-error
# from oauth2client.client import OAuth2WebServerFlow, HttpAccessTokenRefreshError, OAuth2Credentials  # pylint: disable=import-error
# from googleapiclient.http import _should_retry_response  # This is necessary because google masks errors
# from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload  # pylint: disable=import-error

import onedrivesdk
from onedrivesdk.helpers import GetAuthCodeServer
from onedrivesdk.error import OneDriveError

from cloudsync import Provider, OInfo, DIRECTORY, FILE, NOTKNOWN, Event, DirInfo, OType
from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError, CloudFileNotFoundError, \
    CloudFileExistsError, CloudCursorError
from cloudsync.oauth import OAuthConfig
from cloudsync.utils import debug_sig, disable_log_multiline


class OneDriveFileDoneError(Exception):
    pass


log = logging.getLogger(__name__)
logging.getLogger('googleapiclient').setLevel(logging.INFO)
logging.getLogger('googleapiclient.discovery').setLevel(logging.WARN)


class OneDriveInfo(DirInfo):              # pylint: disable=too-few-public-methods
    # oid, hash, otype and path are included here to satisfy a bug in mypy,
    # which does not recognize that they are already inherited from the grandparent class
    oid: str
    hash: Any
    otype: OType
    path: str
    pid: str = None

    def __init__(self, *a, pid=None, **kws):
        super().__init__(*a, **kws)
        self.pid = pid


class OneDriveProvider(Provider):         # pylint: disable=too-many-public-methods, too-many-instance-attributes
    case_sensitive = False
    default_sleep = 15

    provider = 'onedrive'
    name = 'OneDrive'
    _scopes = ['wl.signin', 'wl.offline_access', 'onedrive.readwrite']
    _base_url = 'https://api.onedrive.com/v1.0/'
    additional_invalid_characters = '#'

    def __init__(self, oauth_config: Optional[OAuthConfig] = None):
        super().__init__()
        self.__creds: Optional[Dict[str, str]] = None
        self.__cursor: Optional[str] = None
        self.__client: onedrivesdk.OneDriveClient = None
        self.__root_id: str = None
        self.mutex = threading.RLock()
        self._oauth_config = oauth_config

        # TODO pick a port...just like dropbox
        self._redirect_uri = 'http://localhost:8080/'

    @property
    def connected(self):  # One Drive
        return self.__client is not None

    def get_display_name(self):  # One Drive
        return self.name

    # noinspection PyProtectedMember
    def authenticate(self):  # One Drive
        assert self._oauth_config.app_id

        log.debug("redir %s, appid %s", self._redirect_uri, self._oauth_config.app_id)

        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

        client = onedrivesdk.get_default_client(
            client_id=self._oauth_config.app_id, scopes=self._scopes)

        auth_url = client.auth_provider.get_auth_url(self._redirect_uri)

        # this will block until we have the code
        auth_code = GetAuthCodeServer.get_auth_code(auth_url, self._redirect_uri)

        client.auth_provider.authenticate(auth_code, self._redirect_uri, self._oauth_config.app_secret)

        creds = {"access": client.auth_provider.access_token, 
                 "refresh": client.auth_provider._session.refresh_token,  # pylint: disable=protected-access
                 "url": client.auth_provider._session.auth_server_url,  # pylint: disable=protected-access
                 }

        return creds

    def _get_url(self, api_path):
        api_path = api_path.lstrip("/")
        with self._api() as client:
            return client.base_url + api_path

    def _direct_api(self, action, path=None, *, url=None, stream=None):  # pylint: disable=too-many-branches
        assert path or url
        if not url:
            url = self._get_url(path)
        with self._api() as client:
            if not url:
                path = path.lstrip("/")
                url = client.base_url + path
            req = getattr(requests, action)(
                url,
                stream=stream,
                headers={
                    'Authorization': 'bearer {access_token}'.format(access_token=client.auth_provider.access_token),
                    'content-type': 'application/json'})

        if req.status_code == 204:
            return {}

        if req.status_code > 201:
            dat = req.json()
            emsg = dat['error']['message']
            log.error("%s error %s (%s)", action, str(req.status_code)+" "+emsg, dat['error'])
            if req.status_code == 404:
                raise CloudFileNotFoundError(emsg)
            if dat['error']['code'] == 'unauthenticated':
                raise CloudTokenError(emsg)
            if dat['error']['code'] == 'itemNotFound':
                raise CloudFileNotFoundError(emsg)
            if dat['error']['code'] in ('nameAlreadyExists', 'accessDenied'):
                raise CloudFileExistsError(emsg)
            if req.status_code == 400:
                if dat['error']['code'] == 'invalidRequest':
                    # invalid oid
                    raise CloudFileNotFoundError(emsg)
            if req.status_code == 405:
                if dat['error']['code'] == 'invalidRequest':
                    # expected type to be folder
                    raise CloudFileExistsError(emsg)
            raise CloudDisconnectedError(emsg)

        if stream:
            return req
        return req.json()

    def get_quota(self):
        dat = self._direct_api("get", "drive/")

        res = {
            'used': dat["quota"]["total"]-dat["quota"]["remaining"],
            'total': dat["quota"]["total"],
            'login': dat["owner"]["user"]["displayName"],
            'uid': dat['id']
        }

        return res

    def reconnect(self): 
        self.connect(self.__creds)

    def connect(self, creds):
        if not self.__client:
            log.debug('Connecting to One Drive')
            assert self._oauth_config.app_id
            assert self._oauth_config.app_secret

            assert creds.get("refresh")

            with self._api(needs_client=False):
                http_provider = onedrivesdk.HttpProvider()
                auth_provider = onedrivesdk.AuthProvider(
                        http_provider=http_provider,
                        client_id=self._oauth_config.app_id,
                        scopes=self._scopes)
                auth_provider.get_auth_url(self._redirect_uri)

                class MySession(onedrivesdk.session.Session):
                    def __init__(self, **kws):  # pylint: disable=super-init-not-called
                        self.__dict__ = kws

                    @staticmethod
                    def load_session(**kws):
                        _ = kws
                        return MySession(
                            refresh_token=creds.get("refresh"),
                            access_token=creds.get("access", None),
                            redirect_uri=self._redirect_uri,  # pylint: disable=protected-access
                            auth_server_url=creds.get("url"),
                            client_id=self._oauth_config.app_id,  # pylint: disable=protected-access
                            client_secret=self._oauth_config.app_secret,  # pylint: disable=protected-access
                        )

                auth_provider = onedrivesdk.AuthProvider(
                        http_provider=http_provider,
                        client_id=self._oauth_config.app_id,
                        session_type=MySession,
                        scopes=self._scopes)

                auth_provider.load_session()
                auth_provider.refresh_token()
                self.__client = onedrivesdk.OneDriveClient(self._base_url, auth_provider, http_provider)
                self.__client.item = self.__client.item  # satisfies a lint confusion
                self.__creds = creds

        if not self.connection_id:
            q = self.get_quota()
            self.connection_id = q["uid"]

    def _api(self, *args, **kwargs):
        needs_client = kwargs.get('needs_client', None)
        if needs_client and not self.__client:
            raise CloudDisconnectedError("currently disconnected")
        return self

    def __enter__(self):
        self.mutex.__enter__()
        return self.__client

    def __exit__(self, ty, ex, tb):
        self.mutex.__exit__(ty, ex, tb)

        if ex:
            try:
                raise ex
            except requests.ConnectionError as e:
                raise CloudDisconnectedError("cannot connect %s" % e)
            except (TimeoutError, ):
                self.disconnect()
                raise CloudDisconnectedError("disconnected on timeout")
            except OneDriveError as e:
                if e.code == "itemNotFound":
                    raise CloudFileNotFoundError(str(e))
                if e.code == "nameAlreadyExists":
                    raise CloudFileExistsError(str(e))
                if e.code == "invalidRequest":
                    if "expected type" in str(e).lower():
                        # TODO this is a 405 error code, use that with directapi
                        raise CloudFileExistsError(str(e))
                    if "handle is invalid" in str(e).lower():
                        # TODO this is a 400 error code, use that with directapi
                        raise CloudFileNotFoundError(str(e))
                if e.code == "accessDenied":
                    raise CloudFileExistsError(str(e))
            except Exception:
                pass

    @property
    def root_id(self):
        if not self.__root_id:
            self.__root_id = self.info_oid('root').oid
        return self.__root_id

    def disconnect(self):
        self.__client = None

    @property
    def latest_cursor(self):
        save_cursor = self.__cursor
        self.__cursor = self._get_url("drive/root/oneDrive.delta")
        for _ in self.events():
            pass
        retval = self.__cursor
        self.__cursor = save_cursor
        return retval

        # done = False
        # next_link = None
        # delta_link = None
        # res = self._direct_api("get", path="drive/root/oneDrive.delta")
        # while not done:
        #     delta_link = res.get('@odata.deltaLink')
        #     next_link = res.get('@odata.nextLink')
        #     events = res.get('value')
        #     import pprint
        #     from cloudsync.utils import debug_sig, disable_log_multiline
        #     with disable_log_multiline():
        #         log.debug("events = \n%s", pprint.pformat(events))
        #     if delta_link:
        #         return delta_link
        #     if events and len(events) == 0:
        #         return next_link  # This probably shouldn't happen...
        #     res = self._direct_api("get", url=next_link)
        #
        # if res:
        #     retval = res.get('@odata.nextLink')
        #     log.debug("latest_cursor = %s", retval)
        #     return retval
        # else:
        #     return None

    @property
    def current_cursor(self):
        if not self.__cursor:
            self.__cursor = self.latest_cursor
        return self.__cursor

    @current_cursor.setter
    def current_cursor(self, val):
        if val is None:
            val = self.latest_cursor
        if not isinstance(val, str) and val is not None:
            raise CloudCursorError(val)
        self.__cursor = val

    def events(self) -> Generator[Event, None, None]:      # pylint: disable=too-many-locals, too-many-branches
        page_token = self.current_cursor
        assert page_token
        done = False
        while not done:
            # log.debug("looking for events, timeout: %s", timeout)
            res = self._direct_api("get", url=page_token)
            delta_link = res.get('@odata.deltaLink')
            next_link = res.get('@odata.nextLink')
            events: List = res.get('value')
            new_cursor = next_link or delta_link

            # for change in sorted(events, key=lambda x: x["lastModifiedDateTime"]): # sorting by modtime also works
            for change in reversed(events):
                with disable_log_multiline():
                    log.debug("got event\n%s", pformat(change))
                # {'cTag': 'adDo0QUI1RjI2NkZDNDk1RTc0ITMzOC42MzcwODg0ODAwMDU2MDAwMDA',
                #  'createdBy': {'application': {'id': '4805d153'},
                #                'user': {'displayName': 'erik aronesty', 'id': '4ab5f266fc495e74'}},
                #  'createdDateTime': '2015-09-19T11:14:15.9Z', 'eTag': 'aNEFCNUYyNjZGQzQ5NUU3NCEzMzguMA',
                #  'fileSystemInfo': {
                #      'createdDateTime': '2015-09-19T11:14:15.9Z',
                #      'lastModifiedDateTime': '2015-09-19T11:14:15.9Z'},
                #  'folder': {'childCount': 0, 'folderType': 'document',
                #             'folderView': {'sortBy': 'name', 'sortOrder': 'ascending', 'viewType': 'thumbnails'}},
                #  'id': '4AB5F266FC495E74!338',
                #  'lastModifiedBy': {'application': {'id': '4805d153'}, 'user': {'displayName': 'erik aronesty', 'id': '4ab5f266fc495e74'}},
                #  'lastModifiedDateTime': '2019-11-08T22:13:20.56Z', 'name': 'root',
                #  'parentReference': {'driveId': '4ab5f266fc495e74', 'driveType': 'personal', 'id': '4AB5F266FC495E74!0', 'path': '/drive/root:'},
                #  'root': {}, 'size': 156, 'webUrl': 'https://onedrive.live.com/?cid=4ab5f266fc495e74'}

                ts = arrow.get(change.get('lastModifiedDateTime')).float_timestamp
                oid = change.get('id')
                exists = not change.get('deleted')

                fil = change.get('file')
                fol = change.get('folder')
                if fil:
                    otype = FILE
                elif fol:
                    otype = DIRECTORY
                else:
                    otype = NOTKNOWN

                ohash = None
                path = None
                if exists:
                    if otype == FILE:
                        if 'hashes' in change['file']:
                            ohash = change['file']['hashes']['sha1Hash']
                        else:
                            log.debug("no hash for file? %s", pformat(change))
                            raise Exception("no hash for file")

                    path = self._join_parent_reference_path_and_name(change['parentReference']['path'], change['name'])
                    # path_slow = self._get_path(oid=oid)
                    # assert path == path_slow

                event = Event(otype, oid, path, ohash, exists, ts, new_cursor=new_cursor)

                log.debug("converted event %s as %s", change, event)

                yield event

            if new_cursor and page_token and new_cursor != page_token:
                self.__cursor = new_cursor
            page_token = new_cursor
            if delta_link:
                done = True

    def _walk(self, path, oid):
        for ent in self.listdir(oid):
            current_path = self.join(path, ent.name)
            event = Event(otype=ent.otype, oid=ent.oid, path=current_path, hash=ent.hash, exists=True, mtime=time.time())
            log.debug("walk %s", event)
            yield event
            if ent.otype == DIRECTORY:
                if self.exists_oid(ent.oid):
                    yield from self._walk(current_path, ent.oid)

    def walk(self, path, since=None):
        info = self.info_path(path)
        if not info:
            raise CloudFileNotFoundError(path)
        yield from self._walk(path, info.oid)

    def upload(self, oid, file_like, metadata=None) -> 'OInfo':
        with self._api() as client:
            req = client.item(drive='me', id=oid).content.request()
            req.method = "PUT"
            resp = req.send(data=file_like)
            item = onedrivesdk.Item(json.loads(resp.content))

        return self._info_item(item)

    def create(self, path, file_like, metadata=None) -> 'OInfo':
        if not metadata:
            metadata = {}

        with self._api() as client:
            # TODO: set @microsoft.graph.conflictBehavior to "fail"
            # see https://docs.microsoft.com/en-us/onedrive/developer/rest-api/api/driveitem_createuploadsession?view=odsp-graph-online
            if self.exists_path(path):
                raise CloudFileExistsError()

        pid = self.get_parent_id(path=path)
        _, base = self.split(path)
        with self._api() as client:
            # TODO switch to directapi
            req: onedrivesdk.ItemContentRequest = client.item(drive='me', id=pid).children[base].content.request()
            req.method = "PUT"
            resp = req.send(data=file_like)
            item = onedrivesdk.Item(json.loads(resp.content))

        return self._info_item(item, path=path)

    def download(self, oid, file_like):
        with self._api() as client:
            info = client.item(id=oid).get()

            raw = info.to_dict()
            url = raw['@content.downloadUrl']
            r = self._direct_api('get', url=url, stream=True)
            for chunk in r.iter_content(chunk_size=4096):
                file_like.write(chunk)
                file_like.flush()

    def rename(self, oid, path):  # pylint: disable=too-many-locals, too-many-branches
        with self._api() as client:
            parent, base = self.split(path)

            item = client.item(id=oid)
            info = item.get()

            old_parent_id = info.parent_reference.id

            new_parent_item = client.item(path=parent)
            new_parent_info = new_parent_item.get()
            new_parent_id = new_parent_info.id

            new_info: onedrivesdk.Item = onedrivesdk.Item()

            try:
                updated = False
                if info.name != base:
                    new_info.name = base
                    item.update(new_info)
                    updated = True
                if old_parent_id != new_parent_info.id:
                    new_info.parent_reference = onedrivesdk.ItemReference()
                    new_info.parent_reference.id = new_parent_id
                    updated = True
                if updated:
                    item.update(new_info)
            except onedrivesdk.error.OneDriveError as e:
                if not (e.code == "nameAlreadyExists" and info.folder):
                    log.debug("self not a folder, or not an exists error")
                    raise

                confl = self.info_path(path)
                if not (confl and confl.otype == DIRECTORY):
                    log.debug("conflict not a folder")
                    raise

                try:
                    next(self.listdir(confl.oid))
                    log.debug("folder is not empty")
                    raise
                except StopIteration:
                    pass  # Folder is empty, rename over is ok

                log.debug("remove conflict out of the way")
                self.delete(confl.oid)

                self.rename(oid, path)

        new_path = self._get_path(oid)
        if new_path != path:
            log.error("path mismatch after rename -- wanted %s, got %s", path, new_path)
            assert new_path == path  # must raise, cuz it's in the if block

        return oid

    def _info_from_rest(self, item, root=None):
        name = item["name"]
        if root:
            path = self.join(root, name)
        else:
            raise NotImplementedError()

        oid = item["id"]
        ohash = None
        if "folder" in item:
            otype = DIRECTORY
        else:
            otype = FILE
        if "file" in item:
            hashes = item["file"]["hashes"]
            ohash = hashes.get("sha1Hash")
        pid = item["parentReference"]["id"]
        name = item["name"]
        mtime = item["lastModifiedDateTime"]
        shared = item["createdBy"]["user"]["id"] != self.connection_id

        return OneDriveInfo(oid=oid, otype=otype, hash=ohash, path=path, pid=pid, name=name,
                            mtime=mtime, shared=shared)

    def listdir(self, oid) -> Generator[OneDriveInfo, None, None]:

        res = self._direct_api("get", "drive/items/%s/children" % oid)

        log.debug("listdir %s", res)
        idir = self.info_oid(oid)
        root = idir.path

        items = res.get("value", [])
        next_link = res.get("@odata.nextLink")

        while items:
            for item in items:
                yield self._info_from_rest(item, root=root)

            items = []
            if next_link:
                res = self._direct_api("get", url=next_link)
                items = res.get("value", [])
                next_link = res.get("@odata.nextLink")

    def mkdir(self, path, metadata=None) -> str:    # pylint: disable=arguments-differ
        _ = metadata
        log.debug("mkdir %s", path)

        # boilerplate: probably belongs in base class
        if self.exists_path(path):
            info = self.info_path(path)
            if info.otype == FILE:
                raise CloudFileExistsError(path)
            log.debug("Skipped creating already existing folder: %s", path)
            return info.oid

        pid = self.get_parent_id(path=path)
        log.debug("got pid %s", pid)

        f = onedrivesdk.Folder()
        i = onedrivesdk.Item()
        _, name = self.split(path)
        i.name = name
        i.folder = f

        with self._api() as client:
            item = client.item(drive='me', id=pid).children.add(i)

        return item.id

    def delete(self, oid):
        try:
            with self._api() as client:
                item = client.item(id=oid).get()
                if not item:
                    log.debug("deleted non-existing oid %s", debug_sig(oid))
                    return  # file doesn't exist already...
                info = self._info_item(item)
                if info.otype == DIRECTORY:
                    try:
                        next(self.listdir(oid))
                        raise CloudFileExistsError("Cannot delete non-empty folder %s:%s" % (oid, info.name))
                    except StopIteration:
                        pass  # Folder is empty, delete it no problem
                self._direct_api("delete", "drive/items/%s" % item.id)
        except CloudFileNotFoundError:
            pass

    def exists_oid(self, oid):
        return self._info_oid(oid, path=False) is not None

    def info_path(self, path: str) -> Optional[OInfo]:
        try:
            with self._api() as client:
                item = client.item(path=path).get()
            if item:
                return self._info_item(item)
            else:
                return None
        except CloudFileNotFoundError:
            return None

    def _info_item(self, item, path=None) -> OneDriveInfo:
        if item.folder:
            otype = DIRECTORY
            ohash = None
        else:
            otype = FILE
            ohash = item.file.hashes.sha1_hash

        if path is None:
            path = self._get_path(item=item)

        pid = item.parent_reference.id

        return OneDriveInfo(oid=item.id, otype=otype, hash=ohash, path=path, pid=pid, name=item.name,
                            mtime=item.last_modified_date_time, shared=item.shared)

    def exists_path(self, path) -> bool:
        try:
            with self._api() as client:
                return bool(client.item(path=path).get())
        except CloudFileNotFoundError:
            return False

    def get_parent_id(self, *, path=None, oid=None):
        log.debug("get parent %s", path)
        if not path and not oid:
            return None

        ret = None

        if path:
            ppath = self.dirname(path)
            i = self.info_path(ppath)
            if i:
                ret = i.oid

        if oid:
            i = self.info_oid(oid)
            if i:
                ret = i.pid     # parent id

        if not ret:
            raise CloudFileNotFoundError("parent %s must exist" % ppath)

        return ret

    def _join_parent_reference_path_and_name(self, pr_path, name):
        path = self.join(pr_path, name)
        preamble = "/drive/root:"
        if ':' in path:
            if path.startswith(preamble):
                path = path[len(preamble):]
            else:
                raise Exception("path '%s'(%s, %s) does not start with '%s', time to implement recursion" % (path, pr_path, name, preamble))
        path = urllib.parse.unquote(path)
        return path

    def _get_path(self, oid=None, item=None) -> Optional[str]:
        """get path using oid or item"""
        # TODO: implement caching

        try:
            with self._api() as client:
                if oid is not None and item is None:
                    item = client.item(id=oid).get()

                if item is not None:
                    return self._join_parent_reference_path_and_name(item.parent_reference.path, item.name)

                raise ValueError("_get_path requires oid or item")
        except CloudFileNotFoundError:
            return None

    def info_oid(self, oid, use_cache=True) -> Optional[OneDriveInfo]:
        return self._info_oid(oid)

    def _info_oid(self, oid, path=None) -> Optional[OneDriveInfo]:
        try:
            with self._api() as client:
                item = client.item(id=oid).get()
            return self._info_item(item, path=path)
        except CloudFileNotFoundError:
            return None

    @staticmethod
    def hash_data(file_like) -> str:
        # get a hash from a filelike that's the same as the hash i natively use
        md5 = hashlib.sha1()
        for c in iter(lambda: file_like.read(32768), b''):
            md5.update(c)
        return md5.hexdigest().upper()
