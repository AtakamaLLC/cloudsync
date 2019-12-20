"""
Onedrive provider
"""

# pylint: disable=missing-docstring

# https://dev.onedrive.com/
# https://docs.microsoft.com/en-us/onedrive/developer/rest-api/concepts/upload?view=odsp-graph-online
# https://github.com/OneDrive/onedrive-sdk-python
# https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/msa-oauth?view=odsp-graph-online
# https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/app-registration?view=odsp-graph-online
import os
import time
import logging
from pprint import pformat
import threading
import asyncio
import hashlib
import json
from typing import Generator, Optional, Dict, Any, Iterable, List, Union, cast
import urllib.parse
import webbrowser
from base64 import urlsafe_b64decode, b64encode
import requests
import arrow

import onedrivesdk_fork as onedrivesdk
from onedrivesdk_fork.error import OneDriveError, ErrorCode
import quickxorhash

from cloudsync import Provider, OInfo, DIRECTORY, FILE, NOTKNOWN, Event, DirInfo, OType
from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError, CloudFileNotFoundError, \
    CloudFileExistsError, CloudCursorError, CloudTemporaryError, CloudException, CloudNamespaceError
from cloudsync.oauth import OAuthConfig, OAuthProviderInfo
from cloudsync.registry import register_provider
from cloudsync.utils import debug_sig


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
        """
        Adds "pid (parent id)" to the DirInfo
        """
        super().__init__(*a, **kws)
        self.pid = pid


def open_url(url):
    webbrowser.open(url)


def _get_size_and_seek0(file_like):
    file_like.seek(0, os.SEEK_END)
    size = file_like.tell()
    file_like.seek(0)
    return size


class OneDriveItem():
    """Use to covert oid to path or path to oid.   Don't try to keep it around, or reuse it."""
    def __init__(self, prov, *, oid=None, path=None, pid=None):
        self.__prov = prov
        self.__item = None

        if (oid is None and path is None):
            raise ValueError("Must specify oid or path")

        self.__oid = oid
        self.__path = path
        self.__pid = pid

        if oid is not None:
            self.__sdk_kws = {"id": oid}

        if path:
            self.__sdk_kws = {"path": path}

        self.__drive_id = self.__prov._get_drive_id()
        self.__get = None

    @property
    def pid(self):
        return self.__pid

    @property
    def oid(self):
        return self.__oid

    @property
    def path(self):
        if not self.__path:
            ret = self.get()
            if ret:
                prdrive_path = ret.parent_reference.path
                if not prdrive_path:
                    self.__path = "/"
                else:
                    unused_preamble, prpath = prdrive_path.split(":")
                    prpath = urllib.parse.unquote(prpath)
                    self.__path = self.__prov.join(prpath, ret.name)
        return self.__path

    # todo: get rid of this
    def _sdk_item(self):
        if self.__item:
            return self.__item

        with self.__prov._api() as client:       # pylint:disable=protected-access
            try:
                self.__item = client.item(drive=self.__drive_id, **self.__sdk_kws)
            except ValueError:
                raise CloudFileNotFoundError("Invalid item: %s" % self.__sdk_kws)
            if self.__item is None:
                raise CloudFileNotFoundError("Missing item: %s" % self.__sdk_kws)

        return self.__item

    @property
    def api_path(self):
        if self.__oid:
            return "/drives/%s/items/%s" % (self.__drive_id, self.__oid)
        if self.__path:
            return "/drives/%s/root:%s" % (self.__drive_id, self.__path)
        raise AssertionError("This should not happen, since __init__ verifies that there is one or the other")

    def get(self):
        if not self.__get:
            self.__get = self._sdk_item().get()
        return self.__get

    @property
    def drive_id(self):
        return self.__drive_id

    @property
    def children(self):
        return self._sdk_item().children

    def update(self, info: onedrivesdk.Item):
        return self._sdk_item().update(info)

    @property
    def content(self):
        return self._sdk_item().content


class OneDriveProvider(Provider):         # pylint: disable=too-many-public-methods, too-many-instance-attributes
    case_sensitive = False
    default_sleep = 15
    large_file_size = 1 * 1024 * 1024
    upload_block_size = 4 * 1024 * 1024

    name = 'onedrive'
    _base_url = 'https://graph.microsoft.com/v1.0/'

    _oauth_info = OAuthProviderInfo(
        auth_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        scopes=['profile', 'openid', 'email', 'files.readwrite.all', 'sites.readwrite.all', 'offline_access', 'group.readwrite.all'],
    )

    _additional_invalid_characters = '#'

    def __init__(self, oauth_config: Optional[OAuthConfig] = None):
        super().__init__()
        self._creds: Optional[Dict[str, str]] = None
        self.__cursor: Optional[str] = None
        self.__client: onedrivesdk.OneDriveClient = None
        self.__test_root: str = None
        self._mutex = threading.RLock()
        self._oauth_config = oauth_config
        self.__team_id = None
        self._namespace: str = None
        self._is_biz = None
        self.__drive_to_name: Dict[str, str] = None
        self.__name_to_drive: Dict[str, str] = None

    @property
    def connected(self):
        return self.__client is not None

    @staticmethod
    def _ensure_event_loop():
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

    def _get_url(self, api_path):
        api_path = api_path.lstrip("/")
        with self._api() as client:
            return client.base_url.rstrip("/") + "/" + api_path

    # names of args are compat with requests module
    def _direct_api(self, action, path=None, *, url=None, stream=None, data=None, headers=None, json=None):  # pylint: disable=redefined-outer-name
        assert path or url

        if not url:
            url = self._get_url(path)

        with self._api() as client:
            if not url:
                path = path.lstrip("/")
                url = client.base_url + path
            head = {
                      'Authorization': 'bearer {access_token}'.format(access_token=client.auth_provider.access_token),
                      'content-type': 'application/json'}
            if headers:
                head.update(headers)
            for k in head:
                head[k] = str(head[k])
            log.debug("direct %s %s", action, url)
            req = getattr(requests, action)(
                url,
                stream=stream,
                headers=head,
                json=json,
                data=data)

        if req.status_code == 204:
            return {}

        if req.status_code > 202:
            if not self._raise_converted_error(req=req):
                raise Exception("Unknown error %s %s" % (req.status_code, req.json()))

        if stream:
            return req
        res = req.json()
# very large: uncomment if more detail needed, semicolonn left in for lint prevention
#        log.debug("response %s", res);

        return res

    def _set_drive_list(self):      # pylint: disable=too-many-locals
        all_drives: Dict[str, str] = {}

        # personal drive, including shared folders
        try:
            dat = self._direct_api("get", "/me/drive/")
            all_drives[dat['id']] = "personal"
        except Exception as e:
            log.debug("error getting info about onedrive %s", repr(e))
            raise CloudTokenError("Invalid account, or no onedrive access")

        # team sharepoint drives
        groups = self._direct_api("get", "/groups")
        for group in groups.get("value", []):
            group_name = group["displayName"]
            try:
                drive = self._direct_api("get", "/groups/%s/drive" % group["id"])
                drive_id = drive["id"]
                all_drives[drive_id] = "team/" + group_name
            except (OneDriveError, CloudException) as err:
                log.warning("Failed to get drive info for %s. Exception: %s", group["id"], repr(err))

        try:
            # drives linked to other "sites"
            sites = self._direct_api("get", "/sites?select=siteCollection&$filter=siteCollection/root+ne+null")
            hosts = []
            for site in sites.get('value', []):
                siteid = site.get("siteCollection")["hostname"]
                hosts.append(siteid)
                drives = self._direct_api("get", "/sites/%s/drives" % siteid)
                for drive in drives.get('value', []):
                    drive_id = drive["id"]
                    drive_name = drive["name"]
                    all_drives[drive['id']] = siteid + '/' + drive_name
                # TODO: support subsites
                # ssites = self._direct_api("get","/sites/%s/sites" % siteid)
                # log.info("%s SSITES %s", siteid, ssites)
        except Exception:
            pass

        log.info("ALL DRIVES %s", all_drives)
        self.__drive_to_name = all_drives
        self.__name_to_drive = {v:k for k, v in all_drives.items()}

        # default namespace to personal
        self._namespace = "personal"

    def _raise_converted_error(self, *, ex=None, req=None):      # pylint: disable=too-many-branches
        status = 0
        if ex is not None:
            status = ex.status_code
            msg = str(ex)
            code = ex.code

        if req is not None:
            status = req.status_code
            try:
                dat = req.json()
                msg = dat["error"]["message"]
                code = dat["error"]["code"]
            except json.JSONDecodeError:
                msg = 'Bad Json'
                code = 'BadRequest'

        if status < 300:
            log.error("Not converting err %s %s", ex, req)
            return False

        if status == 404:
            raise CloudFileNotFoundError(msg)
        if status in (429, 503):
            raise CloudTemporaryError(msg)
        if code in ('ErrorInsufficientPermissionsInAccessToken', ErrorCode.Unauthenticated):
            self.disconnect()
            raise CloudTokenError(msg)
        if code == ErrorCode.Malformed:
            raise CloudFileNotFoundError(msg)
        if code == ErrorCode.ItemNotFound:
            raise CloudFileNotFoundError(msg)
        if code == ErrorCode.ResourceModified:
            raise CloudTemporaryError(msg)
        if code == ErrorCode.NameAlreadyExists:
            raise CloudFileExistsError(msg)
        if code == ErrorCode.AccessDenied:
            raise CloudFileExistsError(msg)
        if status == 401:
            self.disconnect()
            raise CloudTokenError(msg)
        if code == "BadRequest":
            if status == 400:
                raise CloudFileNotFoundError(msg)
        if code == ErrorCode.InvalidRequest:
            if status == 405:
                raise CloudFileExistsError(msg)
            if status == 400:
                raise CloudFileNotFoundError(msg)
        if code == "UnknownError":
            raise CloudTemporaryError(msg)

        log.error("Not converting err %s %s", ex, req)
        return False

    def _get_drive_id(self):
        if not self.__client:
            raise CloudDisconnectedError()
        try:
            return self.__name_to_drive[self.namespace]
        except KeyError:
            raise CloudFileNotFoundError("Unknown drive %s" % self.namespace)

    def get_quota(self):
        dat = self._direct_api("get", "/me/drive/")

        log.info("my drive %s", dat)

        display_name = dat["owner"].get("user", {}).get("displayName")
        if not display_name:
            display_name = dat["owner"].get("group", {}).get("displayName")

        res = {
            'used': dat["quota"]["total"]-dat["quota"]["remaining"],
            'limit': dat["quota"]["total"],
            'login': display_name,
            'drive_id': dat['id'],                # drive id
        }

        return res

    def reconnect(self):
        self.connect(self._creds)

    def connect_impl(self, creds):
        if not self.__client or creds != self._creds:
            if not creds:
                raise CloudTokenError("no credentials")
            log.debug('Connecting to One Drive')
            refresh_token = creds.get("refresh", creds.get("refresh_token"))
            if not refresh_token:
                raise CloudTokenError("no refresh token, refusing connection")

            self._ensure_event_loop()

            with self._api(needs_client=False):
                http_provider = onedrivesdk.HttpProvider()
                auth_provider = onedrivesdk.AuthProvider(
                        http_provider=http_provider,
                        client_id=self._oauth_config.app_id,
                        scopes=self._oauth_info.scopes)

                class MySession(onedrivesdk.session.Session):   # pylint: disable=too-few-public-methods
                    def __init__(self, **kws):  # pylint: disable=super-init-not-called
                        self.__dict__ = kws

                    @staticmethod
                    def load_session(**kws):
                        _ = kws
                        return MySession(
                            refresh_token=refresh_token,
                            access_token=creds.get("access_token", None),
                            redirect_uri=None,  # pylint: disable=protected-access
                            auth_server_url=self._oauth_info.token_url,  # pylint: disable=protected-access
                            client_id=self._oauth_config.app_id,  # pylint: disable=protected-access
                            client_secret=self._oauth_config.app_secret,  # pylint: disable=protected-access
                        )

                auth_provider = onedrivesdk.AuthProvider(
                        http_provider=http_provider,
                        client_id=self._oauth_config.app_id,
                        session_type=MySession,
                        scopes=self._oauth_info.scopes)

                auth_provider.load_session()
                try:
                    auth_provider.refresh_token()
                except Exception as e:
                    log.error(e)
                    raise CloudTokenError(str(e))
                token = auth_provider.access_token
                try:
                    segs = token.split('.')
                    if len(segs) > 1:
                        info = json.loads(urlsafe_b64decode(segs[1]+"==="))
                        self.__team_id = info.get("tid")
                        log.debug("got team : %s", self.__team_id)
                except Exception as e:
                    log.debug("can't parse token, maybe not a team : %s", e)

                self.__client = onedrivesdk.OneDriveClient(self._base_url, auth_provider, http_provider)
                self.__client.item = self.__client.item  # satisfies a lint confusion
                self._creds = creds

            self._set_drive_list()

        q = self.get_quota()
        return q["drive_id"]

    def _api(self, *args, needs_client=True, **kwargs):  # pylint: disable=arguments-differ
        if needs_client and not self.__client:
            raise CloudDisconnectedError("currently disconnected")
        return self

    def __enter__(self):
        self._mutex.__enter__()
        return self.__client

    def __exit__(self, ty, ex, tb):
        self._mutex.__exit__(ty, ex, tb)

        if ex:
            try:
                raise ex
            except requests.ConnectionError as e:
                raise CloudDisconnectedError("cannot connect %s" % e)
            except (TimeoutError, ):
                self.disconnect()
                raise CloudDisconnectedError("disconnected on timeout")
            except OneDriveError as e:
                if not self._raise_converted_error(ex=e):
                    raise
            except Exception:
                return False  # False allows the exit handler to act as normal, which does not swallow the exception
        return None

    def disconnect(self):
        with self._mutex:
            self.__client = None

    @property
    def latest_cursor(self):
        save_cursor = self.__cursor
        self.__cursor = self._get_url("/drives/%s/root/delta" % self._get_drive_id())
        log.debug("cursor %s", self.__cursor)
        for _ in self.events():
            pass
        retval = self.__cursor
        self.__cursor = save_cursor
        return retval

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
            events: Union[List, Iterable] = res.get('value')
            new_cursor = next_link or delta_link

            if not self._is_biz:
                # events = sorted(events, key=lambda x: x["lastModifiedDateTime"]): # sorting by modtime also works
                events = reversed(cast(List, events))

            for change in events:
                # uncomment only while debugging, demicolon left in to cause linter to fail
                # log.debug("got event\n%s", pformat(change));

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

                log.debug("event %s", change)

                ohash = None
                path = None
                if exists:
                    if otype == FILE:
                        ohash = self._hash_from_dict(change)

                    path = self._join_parent_reference_path_and_name(change['parentReference'].get('path', '/'), change['name'])

                event = Event(otype, oid, path, ohash, exists, ts, new_cursor=new_cursor)

                log.debug("converted event %s as %s", change, event)

                yield event

            if new_cursor and page_token and new_cursor != page_token:
                self.__cursor = new_cursor
            page_token = new_cursor
            log.debug("new cursor %s", new_cursor)
            if delta_link:
                done = True

    def _hash_from_dict(self, change):
        if 'hashes' in change['file']:
            if self._is_biz:
                ohash = change['file']['hashes'].get('quickXorHash')
            else:
                ohash = change['file']['hashes'].get('sha1Hash')
            if ohash == "":
                ohash = None
        else:
            log.error("no hash for file? %s", pformat(change))
            ohash = None
        return ohash

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
        size = _get_size_and_seek0(file_like)
        if size <= self.large_file_size:
            with self._api() as client:
                req = self._get_item(client, oid=oid).content.request()
                req.method = "PUT"
                try:
                    resp = req.send(data=file_like)
                except onedrivesdk.error.OneDriveError as e:
                    if e.code == ErrorCode.NotSupported:
                        raise CloudFileExistsError("Cannot upload to folder")
                    if e.code == ErrorCode.ResourceModified:
                        # onedrive ocassionally reports etag mismatch errors, even when there's no possibility of conflict
                        # simply retrying here vastly reduces the number of false positive failures
                        resp = req.send(data=file_like)
                    else:
                        raise

                log.debug("uploaded: %s", resp.content)
                # TODO: why not just info_from_rest?
                item = onedrivesdk.Item(json.loads(resp.content))
                return self._info_item(item)
        else:
            with self._api() as client:
                _unused_resp = self._upload_large(self._get_item(client, oid=oid).api_path, file_like, "replace")
            # todo: maybe use the returned item dict to speed this up
            return self.info_oid(oid)

    def create(self, path, file_like, metadata=None) -> 'OInfo':
        if not metadata:
            metadata = {}

        pid = self._get_parent_id(path=path)
        dirname, base = self.split(path)
        size = _get_size_and_seek0(file_like)

        use_large = size > self.large_file_size
        if not use_large:
            if self.exists_path(path):
                raise CloudFileExistsError()
            with self._api() as client:
                api_path = self._get_item(client, oid=pid).api_path
                base = base.replace("'", "''")
                name = urllib.parse.quote(base)
                api_path += "/children('" + name + "')/content"
                r = self._direct_api("put", api_path, data=file_like, headers={'content-type': 'text/plain'})
            return self._info_from_rest(r, root=dirname)
        else:
            with self._api() as client:
                r = self._upload_large(self._get_item(client, path=path).api_path + ":", file_like, conflict="fail")
            return self._info_from_rest(r, root=self.dirname(path))

    def _upload_large(self, drive_path, file_like, conflict):
        size = _get_size_and_seek0(file_like)
        r = self._direct_api("post", "%s/createUploadSession" % drive_path, json={"item": {"@microsoft.graph.conflictBehavior": conflict}})
        upload_url = r["uploadUrl"]

        data = file_like.read(self.upload_block_size)

        cbfrom = 0
        while data:
            clen = len(data)             # fragment content size
            cbto = cbfrom + clen - 1     # inclusive content byte range
            cbrange = "bytes %s-%s/%s" % (cbfrom, cbto, size)
            r = self._direct_api("put", url=upload_url, data=data, headers={"Content-Length": clen, "Content-Range": cbrange})
            data = file_like.read(self.upload_block_size)
            cbfrom = cbto + 1
        return r

    def list_ns(self):
        return list(n for n in self.__name_to_drive)

    def download(self, oid, file_like):
        with self._api() as client:
            info = self._get_item(client, oid=oid)
            r = self._direct_api("get", info.api_path + "/content", stream=True)
            for chunk in r.iter_content(chunk_size=4096):
                file_like.write(chunk)
                file_like.flush()

    def rename(self, oid, path):  # pylint: disable=too-many-locals, too-many-branches, too-many-statements
        with self._api() as client:
            self._verify_parent_folder_exists(path)
            parent, base = self.split(path)

            item = self._get_item(client, oid=oid)
            info = item.get()

            old_parent_id = info.parent_reference.id

            new_parent_item = self._get_item(client, path=parent)
            new_parent_info = new_parent_item.get()
            new_parent_id = new_parent_info.id

            new_info: onedrivesdk.Item = onedrivesdk.Item()

            try:
                updated = False
                if info.name != base:
                    need_temp = False
                    if info.name.lower() == base.lower():
                        need_temp = True
                    if need_temp:
                        new_info.name = base + os.urandom(8).hex()
                        item.update(new_info)
                    new_info.name = base
                    updated = True
                if old_parent_id != new_parent_info.id:
                    new_info.parent_reference = onedrivesdk.ItemReference()
                    new_info.parent_reference.id = new_parent_id
                    updated = True
                if updated:
                    item.update(new_info)
            except onedrivesdk.error.OneDriveError as e:
                if e.code == ErrorCode.InvalidRequest:
                    base, location = self.split(path)
                    parent_item = self.info_path(base, use_cache=False)
                    while location:
                        if parent_item and parent_item.otype is OType.FILE:
                            raise CloudFileExistsError()
                        base, location = self.split(base)
                        parent_item = self.info_path(base, use_cache=False)
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

                if confl.oid == oid:
                    raise
                
                log.debug("remove conflict out of the way : %s", e)
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

        iid = item["id"]
        ohash = None
        if "folder" in item:
            otype = DIRECTORY
        else:
            otype = FILE
        if "file" in item:
            ohash = self._hash_from_dict(item)

        pid = item["parentReference"].get("id")
        name = item["name"]
        mtime = item["lastModifiedDateTime"]
        shared = False
        if "createdBy" in item:
            shared = bool(item.get("remoteItem"))

        return OneDriveInfo(oid=iid, otype=otype, hash=ohash, path=path, pid=pid, name=name,
                            mtime=mtime, shared=shared)

    def listdir(self, oid) -> Generator[OneDriveInfo, None, None]:
        with self._api() as client:
            api_path = self._get_item(client, oid=oid).api_path

        res = self._direct_api("get", "%s/children" % api_path)

        idir = self.info_oid(oid)
        root = idir.path

        items = res.get("value", [])
        next_link = res.get("@odata.nextLink")

        while items:
            for item in items:
#                log.debug("listdir %s", item)
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

        pid = self._get_parent_id(path=path)
        log.debug("got pid %s", pid)

        f = onedrivesdk.Folder()
        i = onedrivesdk.Item()
        _, name = self.split(path)
        i.name = name
        i.folder = f

        with self._api() as client:
            item = self._get_item(client, oid=pid).children.add(i)

        return item.id

    def delete(self, oid):
        try:
            with self._api() as client:
                item = self._get_item(client, oid=oid).get()
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
                self._direct_api("delete", self._get_item(client, oid=oid).api_path)
        except CloudFileNotFoundError:
            pass

    def exists_oid(self, oid):
        return self._info_oid(oid, path=False) is not None

    def info_path(self, path: str, use_cache=True) -> Optional[OInfo]:
        log.debug("info path %s", path)
        try:
            if path == "/":
                return OneDriveInfo(oid="root", otype=DIRECTORY, hash=None, path="/", pid=None, name="",
                        mtime=None, shared=False)

            with self._api() as client:
                api_path = self._get_item(client, path=path).api_path
            log.debug("direct res path %s", api_path)
            res = self._direct_api("get", api_path)
            return self._info_from_rest(res, root=self.dirname(path))
        except CloudFileNotFoundError:
            return None

    def _info_item(self, item, path=None) -> OneDriveInfo:
        if item.folder:
            otype = DIRECTORY
            ohash = None
        else:
            otype = FILE

            if self._is_biz:
                ohash = item.file.hashes.to_dict()["quickXorHash"]
            else:
                ohash = item.file.hashes.to_dict()["sha1Hash"]

        pid = item.parent_reference.id

        odi = OneDriveItem(self, oid=item.id, path=path, pid=pid)

        if path is None:
            path = odi.path

        return OneDriveInfo(oid=odi.oid, otype=otype, hash=ohash, path=odi.path, pid=odi.pid, name=item.name,
                            mtime=item.last_modified_date_time, shared=item.shared)

    def exists_path(self, path) -> bool:
        try:
            with self._api() as client:
                return bool(self._get_item(client, path=path).get())
        except CloudFileNotFoundError:
            return False

    def _get_parent_id(self, *, path=None, oid=None):
        log.debug("get parent %s", path)
        if not path and not oid:
            log.error("invalid info %s %s", path, oid)
            raise CloudFileNotFoundError("Invalid path/oid")

        ret = None

        if path:
            ppath = self.dirname(path)
            i = self.info_path(ppath)
            if i:
                ret = i.oid
                if i.otype == FILE:
                    raise CloudFileExistsError("file where a folder should be")

        if oid is not None:
            i = self.info_oid(oid)
            if i:
                ret = i.pid     # parent id

        if not ret:
            raise CloudFileNotFoundError("parent %s must exist" % ppath)

        return ret

    def _drive_root(self, name, path=""):       # pylint:disable=no-self-use
        return "/drives/%s/root:" % name + path

    def _join_parent_reference_path_and_name(self, pr_path, name):
        path = self.join(pr_path, name)
        preambles = ["/drive/root:", "/me/drive/root:", "/drives/%s/root:" % self.connection_id]
        for did in self.__drive_to_name:
            preambles.append("/drives/%s/root:" % did)

        if ':' in path:
            found = False
            for preamble in preambles:
                if path.startswith(preamble):
                    path = path[len(preamble):]
                    found = True
                    break
            if not found:
                raise Exception("path '%s'(%s, %s) does not start with '%s', maybe implement recursion?" % (path, pr_path, name, preambles))
        path = urllib.parse.unquote(path)
        return path

    def _get_item(self, client, *, oid=None, path=None):
        if not client:
            raise CloudDisconnectedError("Not connected")
        return OneDriveItem(self, oid=oid, path=path)

    def _get_path(self, oid=None) -> Optional[str]:
        """get path using oid or item"""
        # TODO: implement caching

        try:
            with self._api() as client:
                item = self._get_item(client, oid=oid)

                if item is not None:
                    return item.path

                raise ValueError("_box_get_path requires oid or item")
        except CloudFileNotFoundError:
            return None

    def info_oid(self, oid: str, use_cache=True) -> Optional[OneDriveInfo]:
        return self._info_oid(oid)

    def _info_oid(self, oid, path=None) -> Optional[OneDriveInfo]:
        try:
            with self._api() as client:
                try:
                    item = self._get_item(client, oid=oid).get()
                except OneDriveError as e:
                    if e.code == 400:
                        log.debug("malformed oid %s: %s", oid, e)
                        # malformed oid == not found
                        return None
                    raise
            return self._info_item(item, path=path)
        except CloudFileNotFoundError:
            return None

    def hash_data(self, file_like) -> str:
        # get a hash from a filelike that's the same as the hash i natively use
        if self._is_biz:
            h = quickxorhash.quickxorhash()
            for c in iter(lambda: file_like.read(32768), b''):
                h.update(c)
            return b64encode(h.digest()).decode("utf8")
        else:
            h = hashlib.sha1()
            for c in iter(lambda: file_like.read(32768), b''):
                h.update(c)
            return h.hexdigest().upper()

    @property                                # type: ignore
    def namespace(self) -> str:              # type: ignore
        return self._namespace

    @namespace.setter
    def namespace(self, ns: str):
        self._namespace = ns
        dat = self._direct_api("get", "/drives/%s/" % self._get_drive_id())
        self._is_biz = dat["driveType"] != 'personal'

    @property
    def namespace_id(self) -> Optional[str]:
        return self._get_drive_id()

    @namespace_id.setter
    def namespace_id(self, ns_id: str):
        if ns_id not in self.__drive_to_name:
            raise CloudNamespaceError("The namespace id specified was invalid")
        self.namespace = self.__drive_to_name[ns_id]

    @classmethod
    def test_instance(cls):
        return cls.oauth_test_instance(prefix=cls.name.upper(), port_range=(54200, 54210), host_name="localhost")

    @property
    def _test_namespace(self):
        return "personal"


class OneDriveBusinessTestProvider(OneDriveProvider):
    name = "testodbiz"


register_provider(OneDriveBusinessTestProvider)

__cloudsync__ = OneDriveProvider
