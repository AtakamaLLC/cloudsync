# https://dev.onedrive.com/
# https://docs.microsoft.com/en-us/onedrive/developer/rest-api/concepts/upload?view=odsp-graph-online
# https://github.com/OneDrive/onedrive-sdk-python
# https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/msa-oauth?view=odsp-graph-online
# https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/app-registration?view=odsp-graph-online
import io
import time
import logging
import requests
import threading
from pprint import pformat
from requests import HTTPError
import hashlib
from ssl import SSLError
import json
from typing import Generator, Optional, List, Dict, Any

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

from cloudsync.utils import debug_args, debug_sig
from cloudsync import Provider, OInfo, DIRECTORY, FILE, NOTKNOWN, Event, DirInfo, OType
from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError, CloudFileNotFoundError, CloudTemporaryError, \
    CloudFileExistsError, CloudCursorError, CloudOutOfSpaceError
from cloudsync.oauth import OAuthConfig


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

    def __init__(self, oauth_config: Optional[OAuthConfig] = None):
        super().__init__()
        self.__creds: Optional[Dict[str, str]] = None
        self.__cursor: Optional[str] = None
        self.__client = None
        self.mutex = threading.RLock()
        self._oauth_config = oauth_config

        # TODO pick a port...just like dropbox
        self._redirect_uri = 'http://localhost:8080/'

    @property
    def connected(self):  # One Drive
        return self.__client is not None

    def get_display_name(self):  # One Drive
        return self.name

    def authenticate(self):  # One Drive
        assert self._oauth_config.app_id

        log.debug("redir %s, appid %s", self._redirect_uri, self._oauth_config.app_id)

        client = onedrivesdk.get_default_client(
            client_id=self._oauth_config.app_id, scopes=self._scopes)

        auth_url = client.auth_provider.get_auth_url(self._redirect_uri)

        # this will block until we have the code
        auth_code = GetAuthCodeServer.get_auth_code(auth_url, self._redirect_uri)

        client.auth_provider.authenticate(auth_code, self._redirect_uri, self._oauth_config.app_secret)

        creds = {"access": client.auth_provider.access_token, 
                 "refresh": client.auth_provider._session.refresh_token,
                 "url": client.auth_provider._session.auth_server_url,
                 }

        return creds

    def _direct_api(self, action, path=None, *, url=None, stream=None):
        assert path or url
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
            log.error("%s error %s", action, str(req.status_code)+" "+req.json()['error']['message'])
            if req.json()['error']['code'] == 'unauthenticated':
                raise CloudTokenError(req.json()['error']['message'])
            raise CloudDisconnectedError(req.json()['error']['message'])

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

    def connect(self, creds): # GD
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
                auth_url = auth_provider.get_auth_url(self._redirect_uri)

                class MySession(onedrivesdk.session.Session):
                    def __init__(self, **kws):
                        self.__dict__ = kws

                    @staticmethod
                    def load_session(**kws):
                        return MySession(
                            refresh_token = creds.get("refresh"),
                            access_token = creds.get("access", None),
                            redirect_uri = self._redirect_uri,
                            auth_server_url = creds.get("url"),
                            client_id = self._oauth_config.app_id,
                            client_secret = self._oauth_config.app_secret,
                        )

                auth_provider = onedrivesdk.AuthProvider(
                        http_provider=http_provider,
                        client_id=self._oauth_config.app_id,
                        session_type=MySession,
                        scopes=self._scopes)

                auth_provider.load_session()
                auth_provider.refresh_token()
                self.__client = onedrivesdk.OneDriveClient(self._base_url, auth_provider, http_provider)
                self.__creds = creds

        if not self.connection_id:
            q = self.get_quota()
            self.connection_id = q["uid"]


    @staticmethod
    def _get_reason_from_http_error(e): # GD
        # gets a default something (actually the message, not the reason) using their secret interface
        reason = e._get_reason()  # pylint: disable=protected-access

        # parses the JSON of the content to get the reason from where it really lives in the content
        try:  # this code was copied from googleapiclient/http.py:_should_retry_response()
            data = json.loads(e.content.decode('utf-8'))
            if isinstance(data, dict):
                reason = data['error']['errors'][0]['reason']
            else:
                reason = data[0]['error']['errors']['reason']
        except (UnicodeDecodeError, ValueError, KeyError):
            log.warning('Invalid JSON content from response: %s', e.content)

        return reason

    @staticmethod
    def __escape(filename: str): # GD
        ret = filename
        ret = ret.replace("\\", "\\\\")
        ret = ret.replace("'", "\\'")
        return ret

    def _api(self, needs_client=True):
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
            except onedrivesdk.error.OneDriveError as e:
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
    def root_id(self): # GD
        if not self.__root_id:
            res = self._api('files', 'get',
                            fileId='root',
                            fields='id',
                            )
            self.__root_id = res['id']
            self._ids['/'] = self.__root_id
        return self.__root_id

    def disconnect(self): # GD
        self.__client = None

    @property
    def latest_cursor(self): # GD
        res = self._api('changes', 'getStartPageToken')
        if res:
            return res.get('startPageToken')
        else:
            return None

    @property
    def current_cursor(self): # GD
        if not self.__cursor:
            self.__cursor = self.latest_cursor
        return self.__cursor

    @current_cursor.setter
    def current_cursor(self, val): # GD
        if val is None:
            val = self.latest_cursor
        if not isinstance(val, str) and val is not None:
            raise CloudCursorError(val)
        self.__cursor = val

    def events(self) -> Generator[Event, None, None]:      # pylint: disable=too-many-locals, too-many-branches # GD
        page_token = self.current_cursor
        while page_token is not None:
            # log.debug("looking for events, timeout: %s", timeout)
            response = self._api('changes', 'list', pageToken=page_token, spaces='drive',
                                 includeRemoved=True, includeItemsFromAllDrives=True, supportsAllDrives=True)
            new_cursor = response.get('newStartPageToken', None)
            for change in response.get('changes'):
                log.debug("got event %s", change)

                # {'kind': 'drive#change', 'type': 'file', 'changeType': 'file', 'time': '2019-07-23T16:57:06.779Z',
                # 'removed': False, 'fileId': '1NCi2j1SjsPUTQTtaD2dFNsrt49J8TPDd', 'file': {'kind': 'drive#file',
                # 'id': '1NCi2j1SjsPUTQTtaD2dFNsrt49J8TPDd', 'name': 'dest', 'mimeType': 'application/octet-stream'}}

                # {'kind': 'drive#change', 'type': 'file', 'changeType': 'file', 'time': '2019-07-23T20:02:14.156Z',
                # 'removed': True, 'fileId': '1lhRe0nDplA6I5JS18642rg0KIbYN66lR'}

                ts = arrow.get(change.get('time')).float_timestamp
                oid = change.get('fileId')
                exists = not change.get('removed')

                fil = change.get('file')
                if fil:
                    if fil.get('mimeType') == self._folder_mime_type:
                        otype = DIRECTORY
                    else:
                        otype = FILE
                else:
                    otype = NOTKNOWN

                ohash = None
                path = self._path_oid(oid, use_cache=False)

                event = Event(otype, oid, path, ohash, exists, ts, new_cursor=new_cursor)

                remove = []
                for cpath, coid in self._ids.items():
                    if coid == oid:
                        if cpath != path:
                            remove.append(cpath)

                    if path and otype == DIRECTORY and self.is_subpath(path, cpath):
                        remove.append(cpath)

                for r in remove:
                    self._ids.pop(r, None)

                if path:
                    self._ids[path] = oid

                log.debug("converted event %s as %s", change, event)

                yield event

            if new_cursor and page_token and new_cursor != page_token:
                self.__cursor = new_cursor
            page_token = response.get('nextPageToken')

    def _walk(self, path, oid): # GD
        for ent in self.listdir(oid):
            current_path = self.join(path, ent.name)
            event = Event(otype=ent.otype, oid=ent.oid, path=current_path, hash=ent.hash, exists=True, mtime=time.time())
            log.debug("walk %s", event)
            yield event
            if ent.otype == DIRECTORY:
                if self.exists_oid(ent.oid):
                    yield from self._walk(current_path, ent.oid)

    def walk(self, path, since=None): # GD
        info = self.info_path(path)
        if not info:
            raise CloudFileNotFoundError(path)
        yield from self._walk(path, info.oid)

    def __prep_upload(self, path, metadata): # GD
        # modification time
        mtime = metadata.get("modifiedTime", time.time())
        mtime = arrow.get(mtime).isoformat()
        gdrive_info = {
            'modifiedTime':  mtime
        }

        # mime type, if provided
        mime_type = metadata.get("mimeType", None)
        if mime_type:
            gdrive_info['mimeType'] = mime_type

        # path, if provided
        if path:
            _, name = self.split(path)
            gdrive_info['name'] = name

        # misc properties, if provided
        app_props = metadata.get("appProperties", None)
        if app_props:
            # caller can specify google-specific stuff, if desired
            gdrive_info['appProperties'] = app_props

        # misc properties, if provided
        app_props = metadata.get("properties", None)
        if app_props:
            # caller can specify google-specific stuff, if desired
            gdrive_info['properties'] = app_props

        log.debug("info %s", gdrive_info)

        return gdrive_info

    def upload(self, oid, file_like, metadata=None) -> 'OInfo': # GD
        with self._api() as client:
            req = client.item(drive='me', id=oid).content.request()
            req.method = "PUT"
            resp = req.send(data=file_like)
            item = onedrivesdk.Item(json.loads(resp.content))

        return self._info_item(item)

    def create(self, path, file_like, metadata=None) -> 'OInfo': # GD
        if not metadata:
            metadata = {}

        with self._api() as client:
            # TODO: set @microsoft.graph.conflictBehavior to "fail"
            # see https://docs.microsoft.com/en-us/onedrive/developer/rest-api/api/driveitem_createuploadsession?view=odsp-graph-online
            if self.exists_path(path):
                raise CloudFileExistsError()

        pid = self.get_parent_id(path=path)
        parent, base = self.split(path)
        with self._api() as client:
            # TODO switch to directapi
            req = client.item(drive='me', id=pid).children[base].content.request()
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

    def rename(self, oid, path):  # pylint: disable=too-many-locals, too-many-branches # GD
        with self._api() as client:
            parent, base = self.split(path)

            item = client.item(id=oid)
            info = item.get()

            pid = info.parent_reference.id

            pitem = client.item(path=parent)
            pinfo = pitem.get()

            new_info = onedrivesdk.Item()

            try:
                if pid == pinfo.id:
                    new_info.name = base
                    item.update(new_info)
                else:
                    new_info.path = path
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

        return oid

    def listdir(self, oid) -> Generator[OneDriveInfo, None, None]: # GD
        with self._api() as client:
            collection = client.item(drive='me', id=oid).children.request(top=50).get()

            while collection:
                for i in collection:
                    oi = self._info_item(i)
                    yield DirInfo(oi.otype, oi.oid, oi.hash, oi.path)

                # TODO, switch to direct_api
#                collection = onedrivesdk.ChildrenCollectionRequest.get_next_page_request(collection, client).get()
                collection = None


    def mkdir(self, path, metadata=None) -> str:    # pylint: disable=arguments-differ # GD
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
            return self._info_item(item, path=path)
        except CloudFileNotFoundError:
            return None

    def _info_item(self, item, path=None) -> OInfo:
        if item.folder:
            otype = DIRECTORY
            ohash = None
        else:
            otype = FILE
            ohash = item.file.hashes.sha1_hash

        if path is None:
            path = self._get_path(item=item)

        pid = item.parent_reference.id

        return OneDriveInfo(oid=item.id, otype=otype, hash=ohash, path=path, pid=pid)

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

    def _get_path(self, oid=None, item=None) -> Optional[str]:
        """get path using oid or item"""
        # TODO: implement caching

        try:
            with self._api() as client:
                if oid is not None and item is None:
                    item = client.item(id=oid).get()

                if item is not None:
                    parent_folder = item.parent_reference.path
                    path = self.join(parent_folder, item.name)
                    preamble = "/drive/root:/"
                    if path.startswith(preamble):
                        path = path[len(preamble) - 1:]
                    else:
                        raise Exception("path '%s' does not start with '%s', time to implement recursion" % (path, preamble))
                    return path

                raise ValueError("_get_path requires oid or item")
        except CloudFileNotFoundError:
            return None

    def info_oid(self, oid, use_cache=True) -> Optional[OneDriveInfo]:
        return self._info_oid(oid)

    def _info_oid(self, oid, use_cache=True, path=None) -> Optional[OneDriveInfo]:
        try:
            with self._api() as client:
                item = client.item(id=oid).get()
            return self._info_item(item, path=path)
        except CloudFileNotFoundError:
            return None

    @staticmethod
    def hash_data(file_like) -> str: # GD
        # get a hash from a filelike that's the same as the hash i natively use
        md5 = hashlib.md5()
        for c in iter(lambda: file_like.read(32768), b''):
            md5.update(c)
        return md5.hexdigest()
