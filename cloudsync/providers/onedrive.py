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
    pids: List[str] = []
    # oid, hash, otype and path are included here to satisfy a bug in mypy,
    # which does not recognize that they are already inherited from the grandparent class
    oid: str
    hash: Any
    otype: OType
    path: str

    def __init__(self, *a, pids=None, **kws):
        super().__init__(*a, **kws)
        if pids is None:
            pids = []
        self.pids = pids


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
        
        # todo, pick a port...just like dropbox
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

    def _direct_api(self, action, path):
        with self._api() as client:
            req = getattr(requests, action)(client.base_url + path,
                          headers={
                               'Authorization': 'bearer {access_token}'.format(access_token=client.auth_provider.access_token),
                               'content-type': 'application/json'})
        if req.status_code > 201:
            log.error("get_quota error %s", str(req.status_code)+" "+req.json()['error']['message'])
            if req.json()['error']['code'] == 'unauthenticated':
                raise CloudTokenError(req.json()['error']['message'])
            raise CloudDisconnectedError(req.json()['error']['message'])

        return req.json()

    def get_quota(self): # GD
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
        if not metadata:
            metadata = {}
        gdrive_info = self.__prep_upload(None, metadata)

        file_like.seek(0, io.SEEK_END)
        file_size = file_like.tell()
        file_like.seek(0, io.SEEK_SET)

        chunksize = 4 * 1024 * 1024
        resumable = file_size > chunksize
        ul = MediaIoBaseUpload(file_like, mimetype=self._io_mime_type, chunksize=chunksize, resumable=resumable)

        fields = 'id, md5Checksum'

        res = self._api('files', 'update',
                        body=gdrive_info,
                        fileId=oid,
                        media_body=ul,
                        fields=fields)

        log.debug("response from upload %s", res)

        if not res:
            raise CloudTemporaryError("unknown response from drive on upload")

        md5 = res.get('md5Checksum', None)  # can be none if the user tries to upload to a folder
        if md5 is None:
            possible_conflict = self._info_oid(oid)
            if possible_conflict and possible_conflict.otype == DIRECTORY:
                raise CloudFileExistsError("Can only upload to a file: %s" % possible_conflict.path)
        return OInfo(otype=FILE, oid=res['id'], hash=md5, path=None)

    def create(self, path, file_like, metadata=None) -> 'OInfo': # GD
        if not metadata:
            metadata = {}
        gdrive_info = self.__prep_upload(path, metadata)

        if self.exists_path(path):
            raise CloudFileExistsError()

        ul = MediaIoBaseUpload(file_like, mimetype=self._io_mime_type, chunksize=4 * 1024 * 1024)

        fields = 'id, md5Checksum'

        parent_oid = self.get_parent_id(path)

        gdrive_info['parents'] = [parent_oid]

        res = self._api('files', 'create',
                        body=gdrive_info,
                        media_body=ul,
                        fields=fields)

        log.debug("response from create %s : %s", path, res)

        if not res:
            raise CloudTemporaryError("unknown response from drive on upload")

        self._ids[path] = res['id']

        log.debug("path cache %s", self._ids)

        return OInfo(otype=FILE, oid=res['id'], hash=res['md5Checksum'], path=path)

    def download(self, oid, file_like): # GD
        req = self._api('files', 'get_media', fileId=oid)
        dl = MediaIoBaseDownload(file_like, req, chunksize=4 * 1024 * 1024)
        done = False
        while not done:
            try:
                _, done = self._api('media', 'next_chunk', dl)
            except OneDriveFileDoneError:
                done = True

    def rename(self, oid, path):  # pylint: disable=too-many-locals, too-many-branches # GD
        pid = self.get_parent_id(path)

        add_pids = [pid]
        if pid == 'root':
            add_pids = [self.root_id]

        info = self._info_oid(oid)
        if info is None:
            log.debug("can't rename, oid doesn't exist %s", debug_sig(oid))
            raise CloudFileNotFoundError(oid)
        remove_pids = info.pids
        old_path = info.path

        _, name = self.split(path)
        body = {'name': name}

        if self.exists_path(path):
            possible_conflict = self.info_path(path)
            if FILE in (info.otype, possible_conflict.otype):
                if possible_conflict.oid != oid:  # it's OK to rename a file over itself, frex, to change case
                    raise CloudFileExistsError(path)
            else:
                if possible_conflict.oid != oid:
                    try:
                        next(self.listdir(possible_conflict.oid))
                        raise CloudFileExistsError("Cannot rename over non-empty folder %s" % path)
                    except StopIteration:
                        # Folder is empty, rename over it no problem
                        if possible_conflict.oid != oid:  # delete the target if we're not just changing case
                            self.delete(possible_conflict.oid)

        if not old_path:
            for cpath, coid in list(self._ids.items()):
                if coid == oid:
                    old_path = cpath


        if add_pids == remove_pids:
            add_pids_str = ""
            remove_pids_str = ""
        else:
            add_pids_str = ",".join(add_pids)
            remove_pids_str = ",".join(remove_pids)

        self._api('files', 'update', body=body, fileId=oid, addParents=add_pids_str, removeParents=remove_pids_str, fields='id')

        if old_path:
            for cpath, coid in list(self._ids.items()):
                relative = self.is_subpath(old_path, cpath)
                if relative:
                    new_cpath = self.join(path, relative)
                    self._ids.pop(cpath)
                    self._ids[new_cpath] = coid

        log.debug("renamed %s -> %s", debug_sig(oid), body)

        return oid

    def listdir(self, oid) -> Generator[OneDriveInfo, None, None]: # GD
        with self._api() as client:
            collection = client.item(drive='me', id=oid).children.request(top=50).get()

            while collection:
                for i in collection:
                    oi = self._info_item(i)
                    yield DirInfo(oi.otype, oi.id, oi.ohash, oi.path)

                collection = onedrivesdk.ChildrenCollectionRequest.get_next_page_request(collection, client).get()


    def mkdir(self, path, metadata=None) -> str:    # pylint: disable=arguments-differ # GD
        log.debug("mkdir %s", path)

        # boilerplate: probably belongs in base class
        if self.exists_path(path):
            info = self.info_path(path)
            if info.otype == FILE:
                raise CloudFileExistsError(path)
            log.debug("Skipped creating already existing folder: %s", path)
            return info.oid

        pid = self.get_parent_id(path)
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
            self._direct_api("delete", "me/drive/items/%s" % item.id)
            item.deleted = True
            item.update()

    def exists_oid(self, oid): # GD
        return self._info_oid(oid) is not None

    def info_path(self, path: str) -> Optional[OInfo]:  # pylint: disable=too-many-locals # GD
        try:
            with self._api() as client:
                item = client.item(path=path).get()
            return self._info_item(item)
        except CloudFileNotFoundError:
            return None

    def _info_item(self, item) -> OInfo:
        if item.folder:
            otype = DIRECTORY
        else:
            otype = FILE
        return OInfo(oid=item.id, otype=otype, hash=None, path="TODO")

    def exists_path(self, path) -> bool: # GD
        try:
            with self._api() as client:
                return bool(client.item(path=path).get())
        except CloudFileNotFoundError:
            return False

    def get_parent_id(self, path):
        log.debug("get parent %s", path)
        if not path:
            return None

        parent, _ = self.split(path)

        if parent == "/":
            return "root"

        # it may have changed, or case may be different, etc.
        info = self.info_path(parent)
        if not info:
            raise CloudFileNotFoundError("parent %s must exist" % parent)

        return info.oid

    def _path_oid(self, oid, info=None, use_cache=True) -> Optional[str]: # GD
        """convert oid to path"""
        if use_cache:
            for p, pid in self._ids.items():
                if pid == oid:
                    return p

            for p, pid in self._trashed_ids.items():
                if pid == oid:
                    return p

        # todo, better cache, keep up to date, etc.

        if not info:
            info = self._info_oid(oid)

        if info and info.pids and info.name:
            ppath = self._path_oid(info.pids[0])
            if ppath:
                path = self.join(ppath, info.name)
                self._ids[path] = oid
                return path
        return None

    def info_oid(self, oid, use_cache=True) -> Optional[OneDriveInfo]:
        return self._info_oid(oid)

    def _info_oid(self, oid, use_cache=True) -> Optional[OneDriveInfo]: # GD
        try:
            with self._api() as client:
                item = client.item(id=oid).get()
            return self._info_item(item)
        except CloudFileNotFoundError:
            return None

    @staticmethod
    def hash_data(file_like) -> str: # GD
        # get a hash from a filelike that's the same as the hash i natively use
        md5 = hashlib.md5()
        for c in iter(lambda: file_like.read(32768), b''):
            md5.update(c)
        return md5.hexdigest()
