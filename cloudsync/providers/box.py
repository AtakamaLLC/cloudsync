import threading
import logging
import json
import hashlib
import time
from typing import Optional, Generator, Dict, Tuple, Any, List
import requests
import arrow

import boxsdk
from boxsdk import Client, JWTAuth, OAuth2
from boxsdk.object.item import Item as BoxItem
from boxsdk.object.folder import Folder as BoxFolder
from boxsdk.object.file import File as BoxFile
from boxsdk.object.event import Event as BoxEvent
from boxsdk.exception import BoxAPIException, BoxNetworkException, BoxOAuthException, BoxValueError
from boxsdk.session.session import Session, AuthorizedSession

from cloudsync.hierarchical_cache import HierarchicalCache
from cloudsync import Provider, OInfo, DIRECTORY, FILE, NOTKNOWN, Event, DirInfo, OType, LongPollManager
from cloudsync.provider import Hash, Cursor

from cloudsync.oauth import OAuthConfig, OAuthProviderInfo

from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError, CloudFileNotFoundError, \
    CloudFileExistsError, CloudException, CloudCursorError

log = logging.getLogger(__name__)
logging.getLogger('boxsdk.network.default_network').setLevel(logging.ERROR)
logging.getLogger('urllib3.connectionpool').setLevel(logging.INFO)

# TODO:
#   refactor _api to produce the client or a box_object, or consider if I want to switch to the RESTful api instead

# Dox:
#   sdk:
#       https://github.com/box/box-python-sdk
#       https://github.com/box/box-python-sdk/blob/master/docs/usage
#       https://box-python-sdk.readthedocs.io/en/stable/index.html
#   api:
#      https://developer.box.com/en/reference/

old_request = Session.request


def patched_request(*a, **kw):
    if "timeout" not in kw:
        kw["timeout"] = 60
    return old_request(*a, **kw)


Session.request = patched_request


class BoxProvider(Provider):  # pylint: disable=too-many-instance-attributes, too-many-public-methods
    """
    Box.com cloud provider
    """
    _events_to_track = ['ITEM_COPY', 'ITEM_CREATE', 'ITEM_MODIFY', 'ITEM_MOVE', 'ITEM_RENAME', 'ITEM_TRASH',
                        'ITEM_UNDELETE_VIA_TRASH', 'ITEM_UPLOAD']

    _oauth_info = OAuthProviderInfo(auth_url='https://account.box.com/api/oauth2/authorize',  # self._auth_url,
                                    token_url="https://api.box.com/oauth2/token",  # self._token_url,
                                    scopes=[]  # self._scopes
                                    )
    _base_box_url = 'https://api.box.com/2.0'
    _events_endpoint = '/events'
    name = 'box'
    _listdir_page_size = 5000
    default_sleep = 10

    def __init__(self, oauth_config: Optional[OAuthConfig] = None):
        """
        Create a new Box.com cloud provider connection.

        Args:
            oauth_config: the oauth config for your client app
        """
        super().__init__()

        self.__cursor: Optional[Cursor] = None
        self.__client: Client = None
        self.__creds: Optional[Dict[str, str]] = None
        self.__long_poll_config: Dict[str, Any] = {}
        self.__long_poll_session = requests.Session()
        self._long_poll_timeout = 120

        self.__access_token = None
        self._mutex = threading.RLock()

        self._oauth_config = oauth_config
        self._long_poll_manager = LongPollManager(self._short_poll, self._long_poll, short_poll_only=False)
        self._ids: Dict[str, str] = {}
        self.__seen_events: Dict[str, float] = {}
        self.__event_sequence: Dict[str, int] = {}
        metadata_template = {"hash": str, "mtime": float, "readonly": bool, "shared": bool, "size": int}
        # TODO: hardcoding '0' as the root oid seems fishy... we should be *asking* for the root oid,
        #   but we can't here, because we aren't connected. we could delay creating the cache, but what
        #   a logistical nightmire that is...
        self.__cache = HierarchicalCache(self, '0', metadata_template=metadata_template)
        self.__root_id = None

    def get_quota(self):
        with self._api() as client:
            url = client.user(user_id='me').get_url()
            log.debug("url = %s", url)
            user = client.make_request('GET', url).json()
            log.debug("json resp = %s", user)
            # {'type': 'user', 'id': '8506151483', 'name': 'Atakama JWT',
            # 'login': 'AutomationUser_813890_GmcM3Cohcy@boxdevedition.com',
            # 'space_amount': 10737418240,
            # 'space_used': 5551989,
            # 'created_at': '2019-05-29T08:35:19-07:00', 'modified_at': '2019-12-04T10:39:14-08:00',
            # 'language': 'en', 'timezone': 'America/Los_Angeles', 'max_upload_size': 5368709120, 'status': 'active',
            # 'job_title': '', 'phone': '', 'address': '',
            # 'avatar_url': 'https://app.box.com/api/avatar/large/8506151483', 'notification_email': []}
            res = {
                'used': user['space_used'],  # CAUTION: 'used' is cached at the server , so won't be updated right away
                'limit': user['space_amount'],
                'login': user['login'],
            }

            log.debug("quota %s", res)
            return res

    def _store_refresh_token(self, access_token, refresh_token):
        self.__creds = {"access_token": access_token, "refresh_token": refresh_token}
        self.__access_token = access_token
        self._oauth_config.creds_changed(self.__creds)

    # noinspection PyUnresolvedReferences
    def connect_impl(self, creds):
        log.debug('Connecting to box')
        if not self.__client or creds != self.__creds:
            try:
                if creds:
                    self.__creds = creds
                else:
                    raise CloudTokenError("no creds")

                jwt_token = creds.get('jwt_token')
                access_token = creds.get('access_token')
                refresh_token = creds.get('refresh_token')

                if not jwt_token:
                    if not ((self._oauth_config.app_id and self._oauth_config.app_secret) and (refresh_token or access_token)):
                        raise CloudTokenError("require app_id/secret and either access_token or refresh token")

                with self._mutex:
                    box_session = Session()
                    box_kwargs = box_session.get_constructor_kwargs()
                    box_kwargs["api_config"] = boxsdk.config.API
                    box_kwargs["default_network_request_kwargs"] = {"timeout": 60}

                    if jwt_token:
                        jwt_dict = json.loads(jwt_token)
                        user_id = creds.get('user_id')
                        auth = JWTAuth.from_settings_dictionary(jwt_dict, user=user_id,
                                                                store_tokens=self._store_refresh_token)
                    else:
                        if not refresh_token:
                            raise CloudTokenError("Missing refresh token")
                        auth = OAuth2(client_id=self._oauth_config.app_id,
                                      client_secret=self._oauth_config.app_secret,
                                      access_token=access_token,
                                      refresh_token=refresh_token,
                                      store_tokens=self._store_refresh_token)

                    box_session = AuthorizedSession(auth, **box_kwargs)
                    self.__client = Client(auth, box_session)
                with self._api():
                    self.__access_token = auth.access_token
                    self._long_poll_manager.start()
            except BoxNetworkException as e:
                log.exception("Error during connect %s", e)
                self.disconnect()
                raise CloudDisconnectedError()
            except (CloudTokenError, CloudDisconnectedError):
                raise
            except Exception as e:
                log.exception("Error during connect %s", e)
                self.disconnect()
                raise CloudTokenError()

        with self._api() as client:
            return client.user(user_id='me').get().id

    def disconnect(self):
        super().disconnect()
        self._long_poll_manager.stop(forever=False)
        self.__client = None
        self.connection_id = None

    # noinspection PyBroadException,PyProtectedMember
    class _BoxProviderGuard:
        def __init__(self, client: Client, box):
            assert isinstance(client, Client)
            self.__client = client
            self.__box = box

        def __enter__(self) -> Client:
            self.__box._mutex.__enter__()
            return self.__client

        def __exit__(self, ty, ex, tb):  # pylint: disable=too-many-branches
            self.__box._mutex.__exit__(ty, ex, tb)

            if ex:
                try:
                    raise ex
                except (TimeoutError,):
                    self.__box.disconnect()
                    raise CloudDisconnectedError("disconnected on timeout")
                except BoxOAuthException as e:
                    self.__box.disconnect()
                    raise CloudTokenError("oauth fail %s" % e)
                except BoxNetworkException as e:
                    self.__box.disconenct()
                    raise CloudDisconnectedError("disconnected %s" % e)
                except BoxValueError:
                    raise CloudFileNotFoundError()
                except BoxAPIException as e:
                    if e.status == 400 and e.code == 'folder_not_empty':
                        raise CloudFileExistsError()
                    if e.status == 404 and e.code == 'not_found':
                        raise CloudFileNotFoundError()
                    if e.status == 404 and e.code == 'trashed':
                        raise CloudFileNotFoundError()
                    if e.status == 405 and e.code == 'method_not_allowed':
                        raise PermissionError()
                    if e.status == 409 and e.code == 'item_name_in_use':
                        raise CloudFileExistsError()
                    if e.status == 400 and e.code == 'invalid_grant':
                        raise CloudTokenError()
                    log.exception("unknown box exception: \n%s", e)
                except CloudException:
                    raise
                except Exception:
                    pass  # this will not swallow the exception, because this is in a context manager

    # noinspection PyProtectedMember
    def _api(self, *args, **kwargs) -> 'BoxProvider._BoxProviderGuard':
        needs_client = kwargs.get('needs_client', True)
        if needs_client and not self.__client:
            raise CloudDisconnectedError("currently disconnected")
        return self._BoxProviderGuard(self.__client, self)

    @property
    def latest_cursor(self) -> Optional[Cursor]:
        with self._api() as client:
            res = client.events().get_latest_stream_position()
            if res:
                return res
            else:
                return None

    @property
    def current_cursor(self) -> Cursor:
        if not self.__cursor:
            self.__cursor = self.latest_cursor
        return self.__cursor

    @current_cursor.setter
    def current_cursor(self, val: Cursor) -> None:  # pylint: disable=no-self-use, unused-argument
        if val is None:
            val = self.latest_cursor
        if not isinstance(val, int) and val is not None:
            raise CloudCursorError(val)
        self._long_poll_manager.unblock()
        self.__cursor = val

    def _long_poll(self, timeout: float) -> bool:
        # we need to always return true, since box has no guarantees
        # this is just an elaborate sleep function
        log.debug("inside _long_poll %s", timeout)
        if not self.__access_token:
            log.warning("No access token in long poll")
        try:
            if self.__long_poll_config.get('retries_remaining', 0) < 1:
                log.debug("creds = %s", self.__creds)
                headers = {'Authorization': 'Bearer %s' % (self.__access_token,)}
                log.debug("headers: %s", headers)
                srv_resp: requests.Response = self.__long_poll_session.options(self._base_box_url + self._events_endpoint,
                                                                               headers=headers, timeout=timeout)
                log.debug("response content is %s, %s", srv_resp.status_code, srv_resp.content)
                if not 200 <= srv_resp.status_code < 300:
                    raise CloudTokenError(srv_resp)
                server_json = srv_resp.json().get('entries')[0]
                self.__long_poll_config = {
                    "url": server_json.get('url'),
                    "retries_remaining": int(server_json.get('max_retries')),
                    "retry_timeout": int(server_json.get('retry_timeout'))
                }
            srv_resp = self.__long_poll_session.get(self.__long_poll_config.get('url'),
                                                    timeout=timeout)  # long poll
            srv_resp_dict = srv_resp.json()
            log.debug("server message is %s", srv_resp_dict.get('message'))
            return True
        except requests.exceptions.ReadTimeout:  # need new long poll server:
            log.debug('Timeout during long poll')
            return True
        # TODO except boxerror.too_many_retries (or whatever the exception is called)
        finally:
            self.__long_poll_config['retries_remaining'] = self.__long_poll_config.get('retries_remaining', 1) - 1

    def events(self) -> Generator[Event, None, None]:  # pylint: disable=method-hidden
        yield from self._long_poll_manager()

    def _short_poll(self) -> Generator[Event, None, None]:  # pylint: disable=too-many-locals
        # see: https://developer.box.com/en/reference/resources/realtime-servers/
        log.debug("inside _short_poll() cursor = %s", self.current_cursor)
        with self._api() as client:
            response = client.events().get_events(limit=100, stream_position=self.current_cursor)
        new_position = response.get('next_stream_position')
        change: BoxEvent
        if new_position:
            self.current_cursor = new_position
        else:
            log.error("No new cursor from Box\n", stack_info=True)
        for change in (i for i in response.get('entries') if i.get('event_type')):
            change_source = change.get('source')
            with self._api() as client:
                if self.__seen_events.get(change.event_id):
                    change_source_info = ""
                    if change_source:
                        change_source_info = str(change_source)
                    log.debug("skipped duplicate event %s, %s", change.event_id, change_source_info)
                    continue
                log.debug("got event %s %s", change.event_id, self.current_cursor)
                log.debug("event type is %s", change.get('event_type'))
                self.__seen_events[change.event_id] = time.monotonic()
                ts = arrow.get(change.get('created_at')).float_timestamp
                log.debug("change source is %s", change_source)
                previous_sequence: int = self.__event_sequence.get(change_source.id)
                if previous_sequence:
                    try:
                        current_sequence = int(change_source.sequence_id)
                    except ValueError:  # couldn't convert to int for some reason?
                        pass
                    if current_sequence:
                        if current_sequence < previous_sequence:
                            log.debug("skipped earlier event for OID %s", change_source.id)
                            continue
                        self.__event_sequence[change_source.id] = current_sequence

                if isinstance(change_source, BoxItem):
                    otype = DIRECTORY if type(change_source) is BoxFolder else FILE
                    oid = change_source.id
                    path = self._box_get_path(client, change_source)
                    ohash = change_source.sha1 if type(change_source) is BoxFile else None
                    exists = change_source.item_status == 'active'
                else:
                    log.debug("ignoring event type %s source type %s", change.get('event_type'), type(change_source))
                    continue

            event = Event(otype, oid, path, ohash, exists, ts, new_cursor=new_position)

            old_path = self.__cache.get_path(oid)
            old_type = self.__cache.get_type(oid=oid)
            if (path and old_path != path) or old_type == DIRECTORY:
                self.__cache.delete(path=path)

            # this MUST NOT BE IN A WITH BLOCK
            yield event

    def upload(self, oid, file_like, metadata=None) -> OInfo:
        with self._api() as client:
            box_object: BoxItem = self._get_box_object(client, oid=oid, object_type=FILE, strict=False)
            if box_object is None:
                raise CloudFileNotFoundError()
            if box_object.object_type != 'file':
                raise CloudFileExistsError()
            new_object = box_object.update_contents_with_stream(file_like)
            retval = self._box_get_oinfo(client, new_object)
            return retval

    def create(self, path, file_like, metadata=None) -> OInfo:
        with self._api() as client:
            parent, base = self.split(path)
            parent_object = self._get_box_object(client, path=parent, object_type=DIRECTORY)
            if parent_object is None:
                raise CloudFileNotFoundError()
            # TODO: implement preflight_check on the upload_stream() call
            new_object: BoxFile = parent_object.upload_stream(file_stream=file_like, file_name=base)
            log.debug("caching id %s for file %s", new_object.object_id, path)
            self.__cache.create(path, new_object.object_id)
            retval = self._box_get_oinfo(client, new_object, parent_path=parent)
            return retval

    def download(self, oid, file_like):
        with self._api() as client:
            box_object: BoxItem = self._get_box_object(client, oid=oid, object_type=FILE)
            if box_object is None:
                raise CloudFileNotFoundError()
            box_object.download_to(writeable_stream=file_like)

    def rename(self, oid, path) -> str:  # pylint: disable=too-many-branches
        self.__cache.delete(path=path)
        try:
            with self._api() as client:
                box_object: BoxItem = self._get_box_object(client, oid=oid, object_type=NOTKNOWN, strict=False)  # todo: get object_type from cache
                if box_object is None:
                    self.__cache.delete(oid=oid)
                    raise CloudFileNotFoundError()
                info = self._box_get_oinfo(client, box_object)
                if info.path:
                    old_path = info.path
                else:
                    old_path = self._box_get_path(client, box_object)
                old_parent, _ignored_old_base = self.split(old_path)
                new_parent, new_base = self.split(path)
                if new_parent == old_parent:
                    try:
                        with self._api():
                            retval = box_object.rename(new_base)
                    except CloudFileExistsError:
                        if box_object.object_type == 'file':
                            raise
                        # are we renaming a folder over another empty folder?
                        box_conflict = self._get_box_object(client, path=path, object_type=NOTKNOWN, strict=False)  # todo: get type from cache

                        # should't happen... we just got a FEx error, and we're not moving
                        if box_conflict is None:  # pragma: no cover
                            raise
                        items = self._box_get_items(client, box_conflict, new_parent)
                        if box_conflict.object_type == 'folder' and len(items) == 0:
                            box_conflict.delete()
                        else:
                            raise
                        return self.rename(oid, path)
                else:
                    new_parent_object = self._get_box_object(client, path=new_parent, object_type=DIRECTORY, strict=False)
                    if new_parent_object is None:
                        raise CloudFileNotFoundError()
                    if new_parent_object.object_type != 'folder':
                        raise CloudFileExistsError()

                    retval = box_object.move(parent_folder=new_parent_object, name=new_base)
                self.__cache.rename(old_path, path)
                return retval.id
        except Exception:
            self.__cache.delete(oid=oid)
            raise

    def mkdir(self, path) -> str:
        info = self.info_path(path)
        if info and info.otype == DIRECTORY:
            return info.oid
        log.debug("MKDIR ---------------- path=%s", path)
        with self._api() as client:  # gives us the client we can use in the exception handling block
            try:
                with self._api():  # only for exception translation inside the try
                    parent, base = self.split(path)
                    log.debug("MKDIR ---------------- parent=%s base=%s", parent, base)
                    parent_object: BoxItem = self._get_box_object(client, path=parent, object_type=DIRECTORY)
                    if parent_object is None:
                        raise CloudFileNotFoundError()
                    child_object: BoxFolder = parent_object.create_subfolder(base)
                    self.__cache.mkdir(path, child_object.object_id)
                    log.debug("MKDIR ---------------- path=%s oid=%s", path, child_object.object_id)

                    return child_object.object_id
            except CloudFileExistsError as e:
                self.__cache.delete(path=path)
                try:
                    box_object = self._get_box_object(client, path=path, object_type=DIRECTORY, strict=False)
                except Exception:
                    raise e
                if box_object is None or box_object.object_type != 'folder':
                    raise
                return box_object.object_id
            except Exception:
                self.__cache.delete(path=path)
                raise

    def rmtree(self, oid):
        with self._api() as client:
            box_object = self._get_box_object(client, oid=oid, object_type=DIRECTORY, strict=False)  # todo: get type from cache
            if box_object is None:
                return

            if box_object.object_type == 'file':
                box_object.delete()
            elif self._box_object_is_root(client, box_object):
                for info in self.listdir(oid):
                    self.rmtree(info.oid)
            else:
                box_object.delete(recursive=True)
        self.__cache.delete(oid=oid)

    def delete(self, oid):
        with self._api() as client:
            box_object = self._get_box_object(client, oid=oid, object_type=NOTKNOWN, strict=False)  # todo: get type from cache
            if box_object is None:
                return
            if box_object.object_type == 'file':
                box_object.delete()
            else:
                box_object.delete(recursive=False)
        self.__cache.delete(oid=oid)

    def exists_oid(self, oid):
        if self.__cache.get_type(oid=oid):
            return True
        try:
            with self._api() as client:
                box_object = self._get_box_object(client, oid=oid, object_type=NOTKNOWN, strict=False)  # NOTKNOWN because it's not cached
                if box_object is None:
                    return False
                self._unsafe_box_object_populate(client, box_object)
                return True
        except CloudFileNotFoundError:
            return False

    def exists_path(self, path) -> bool:
        if self.__cache.get_type(path=path):
            return True
        return self.info_path(path) is not None

    def _box_get_items(self, client: Client, box_object: BoxItem, path: str, page_size: Optional[int] = 5000):
        assert isinstance(client, Client)
        if not page_size:
            page_size = 5000
        if box_object.object_type == 'file':
            return []
        entries = list(box_object.get_items(limit=page_size))
        if not path:
            path = self._box_get_path(client, box_object)
        self._cache_collection_entries(client, entries, path)
        return entries

    def listdir(self, oid) -> Generator[DirInfo, None, None]:
        entries: List[BoxItem] = []
        with self._api() as client:
            parent_object = self._get_box_object(client, oid=oid, object_type=DIRECTORY)
            if parent_object is None:
                raise CloudFileNotFoundError()
            parent_path = self._box_get_path(client, parent_object)

            # shitty attempt 1 that fails due to caching in the sdk:
            # entries = parent_object.item_collection['entries']  # don't use this, new children may be missing

            # shitty attempt 2 that fails due to caching in the sdk:
            entries = self._box_get_items(client, parent_object, parent_path, page_size=self._listdir_page_size)
        for entry in entries:
            retval = None
            with self._api() as client:
                if type(entry) is dict:  # Apparently, get_box_object by path returns dicts and by oid returns objects?
                    raise NotImplementedError
                retval = self._box_get_dirinfo(client, entry, parent_path)
            if retval is not None:
                yield retval

            # attempt 3 that (hopefully) avoids those issues, and gets newly created items
            # see https://github.com/box/box-python-sdk#making-api-calls-manually

            # url = parent_object.get_url('items')
            # log.debug("url = %s", url)
            # json_response = client.make_request('GET', url).json()
            # log.debug("json resp = %s", json_response)
            # for entry in json_response['entries']:
            #     log.debug("entry = %s", entry)
            #     collection_entry = self._box_get_dirinfo_from_collection_entry(entry, parent_path)
            #     log.debug("collection_entry = %s", collection_entry)
            #     yield collection_entry

    def hash_data(self, file_like) -> Hash:
        # get a hash from a filelike that's the same as the hash i natively use
        sha1 = hashlib.sha1()
        for c in iter(lambda: file_like.read(32768), b''):
            sha1.update(c)
        return sha1.hexdigest()

    def _box_object_is_root(self, client: Client, box_object: BoxItem):
        assert isinstance(client, Client)
        if not box_object:
            return False
        if box_object.object_type == 'file':
            return False
        if self.__root_id is None:
            self.__root_id = client.root_folder().object_id
        object_is_root = (box_object.object_id == self.__root_id)
        return object_is_root

    def _box_get_path(self, client: Client, box_object: BoxItem, use_cache=True) -> Optional[str]:
        assert isinstance(client, Client)
        if self._box_object_is_root(client, box_object):
            return self.sep
        if use_cache:
            cached_path = self.__cache.get_path(box_object.object_id)
            if cached_path:
                return cached_path
        path_collection = None
        if not hasattr(box_object, 'path_collection'):
            box_object = self._unsafe_box_object_populate(client, box_object)
        if hasattr(box_object, 'path_collection'):
            path_collection = box_object.path_collection
        if path_collection is not None:
            return self._get_path_from_collection(path_collection, box_object.name)
        else:
            # instead of raising, should this be path="", or maybe do the box_object.get(), or something else?
            raise NotImplementedError("oid is %s" % (box_object.object_id, ))

    def _get_path_from_collection(self, path_collection: dict, base_name: str):
        retval_list = []
        entries = path_collection['entries']
        for entry in entries:
            if entry.id != '0':
                retval_list.append(entry.name)
        if base_name:
            retval_list.append(base_name)
        return self.join(retval_list)

    def _box_get_dirinfo(self, client: Client, box_object: BoxItem, parent_path=None) -> Optional[DirInfo]:
        assert isinstance(client, Client)
        oinfo = self._box_get_oinfo(client, box_object, parent_path)
        if not oinfo.path:
            oinfo.path = self._box_get_path(client, box_object)
        if oinfo:
            retval = DirInfo(otype=oinfo.otype, oid=oinfo.oid, hash=oinfo.hash, path=oinfo.path, name=box_object.name,
                             size=0, mtime=None, shared=False, readonly=False)
            # TODO: get the size, mtime, shared and readonly from the box_object
            return retval
        return None

    def _box_get_oinfo(self, client: Client, box_object: BoxItem, parent_path=None, use_cache=True) -> Optional[OInfo]:
        assert isinstance(client, Client)
        if box_object is None:
            return None

        obj_type = DIRECTORY if box_object.object_type == 'folder' else FILE
        if parent_path:
            path = self.join(parent_path, box_object.name)
        else:
            if use_cache:
                path = self.__cache.get_path(box_object.object_id)
            else:
                path = None
        return OInfo(
            oid=box_object.object_id,
            path=path,
            otype=obj_type,
            hash=None if obj_type == DIRECTORY else box_object.sha1,
            size=0  # TODO: get the size from the box_object
        )

    def _box_get_dirinfo_from_collection_entry(self, entry: dict, parent: str = None) -> Optional[DirInfo]:
        if entry is None:
            return None
        if entry.get('item_status') and entry.get('item_status') != "active":
            return None
        name = entry['name']
        path = None
        if parent:
            path = self.join(parent, name)
        elif entry.get('path_collection'):
            path = self._get_path_from_collection(entry.get('path_collection'), name)

        obj_type = DIRECTORY if entry.get('type') == 'folder' else FILE
        dir_info = DirInfo(
            otype=obj_type,
            oid=entry.get('id'),
            path=path,
            hash=None if obj_type == DIRECTORY else entry.get('sha1'),
            # size=None,
            name=name,
            mtime=None,
            shared=False,
            readonly=False
        )
        log.debug("dir_info = %s", dir_info)
        return dir_info

    def info_path(self, path: str, use_cache=True) -> Optional[OInfo]:
        # otype: OType  # fsobject type     (DIRECTORY or FILE)
        # oid: str  # fsobject id
        # hash: Any  # fsobject hash     (better name: ohash)
        # path: Optional[str]  # path
        # size: int
        if path in ("/", ''):
            with self._api() as client:
                box_object = client.root_folder()
                box_object = self._unsafe_box_object_populate(client, box_object)
                return self._box_get_oinfo(client, box_object)

        cached_type = None
        cached_oid = None
        if use_cache:
            cached_type = self.__cache.get_type(path=path)
            cached_oid = self.__cache.get_oid(path=path)
            log.debug("cached oid = %s", cached_oid)

            if cached_type:
                metadata = self.__cache.get_metadata(path=path)
                if metadata:
                    ohash = metadata.get("hash")
                    size = metadata.get("size")
                    if cached_oid and ohash and size:
                        return OInfo(cached_type, cached_oid, ohash, path, size)

        with self._api() as client:
            log.debug("getting box object for %s:%s", cached_oid, path)
            box_object = self._get_box_object(client, oid=cached_oid, path=path, object_type=cached_type or NOTKNOWN, strict=False, use_cache=use_cache)
            log.debug("got box object for %s:%s %s", cached_oid, path, box_object)
            _, dir_info = self.__box_cache_object(client, box_object, path)
            log.debug("dirinfo = %s", dir_info)

        # pylint: disable=no-member
        if dir_info:
            return OInfo(dir_info.otype, dir_info.oid, dir_info.hash, dir_info.path, dir_info.size)
        return None

    def _get_box_object(self, client: Client, oid=None, path=None, object_type: OType = None, strict=True, use_cache=True) -> Optional[BoxItem]:
        assert isinstance(client, Client)
        assert object_type is not None
        assert not strict or object_type in (FILE, DIRECTORY)
        try:
            with self._api():  # just for exception translation inside the try
                unsafe_box_object = self._unsafe_get_box_object(client, oid=oid, path=path, object_type=object_type, strict=strict, use_cache=use_cache)
                retval = unsafe_box_object
                return retval
        except (CloudFileNotFoundError, PermissionError):  # PermissionError is raised on a non-existent OID
            return None

    def __look_for_name_in_collection_entries(self, client: Client, name, collection_entries, object_type, strict):
        assert isinstance(client, Client)
        for entry in collection_entries:
            if entry.name == name:
                found_type = DIRECTORY if entry.object_type == 'folder' else FILE
                if object_type is not OType.NOTKNOWN and found_type != object_type and strict:
                    raise CloudFileExistsError()
                return self._get_box_object(client, oid=entry.object_id, object_type=found_type, strict=strict), found_type
        return None, None

    def __box_get_metadata(self, client: Client, box_object: BoxItem, path=None):
        assert isinstance(client, Client)
        path = path or self._box_get_path(client, box_object)
        parent = None
        if path:
            parent, _ = self.split(path)
        dir_info = self._box_get_dirinfo(client, box_object, parent_path=parent)
        # pylint: disable=no-member
        if dir_info:
            # type hint mtime to a float. for some reason, pylint guesses int...
            metadata = {"size": dir_info.size, "mtime": 0.0}
            metadata.pop('mtime')
            if dir_info.hash:
                metadata["hash"] = dir_info.hash
            if dir_info.mtime:
                metadata["mtime"] = dir_info.mtime
            if dir_info.readonly:
                metadata["readonly"] = dir_info.readonly
            if dir_info.shared:
                metadata["shared"] = dir_info.shared
            return metadata, dir_info
        return None, None

    def _cache_collection_entries(self, client: Client, entries, parent_path):
        assert isinstance(client, Client)
        for entry in entries:
            self.__box_cache_object(client, entry, self.join(parent_path, entry.name))

    def __box_cache_object(self, client: Client, box_object: BoxItem, path=None) -> Tuple[Optional[Dict], Optional[DirInfo]]:
        assert isinstance(client, Client)
        if not box_object:  # this saves from having to check this condition everywhere
            if path:
                self.__cache.delete(path=path)
            return None, None
        path = path or self._box_get_path(client, box_object)
        otype = FILE if box_object.object_type == 'file' else DIRECTORY
        metadata, dir_info = self.__box_get_metadata(client, box_object, path)
        # Do we need to check if we have metadata here? The current code should always return metadata if we have
        # a box_object, which we know we do because of the check above. If we don't get metadata here, we should
        # clear the cache for the current oid, and return right away.

        self.__cache.update(path, otype, box_object.object_id, metadata, keep=True)

        if hasattr(box_object, "item_collection"):  # has to be a folder
            assert len(box_object.item_collection.get('entries', [])) == 0 or path
            for child in box_object.item_collection.get('entries', []):
                child_path = self.join(path, child.name)
                child_otype = FILE if child.object_type == 'file' else DIRECTORY
                self.__cache.update(child_path, child_otype, child.object_id, keep=True)

        return metadata, dir_info

    # noinspection PyTypeChecker
    @staticmethod
    def _unsafe_box_object_populate(client: Client, box_object: BoxItem) -> BoxItem:
        assert isinstance(client, Client)
        retval: BoxItem = box_object.get()
        return retval

    def _unsafe_get_box_object_from_path(self, client: Client,  # pylint: disable=too-many-locals
                                         path: str,
                                         object_type: OType,
                                         strict: bool,
                                         use_cache: bool) -> Optional[BoxItem]:
        assert isinstance(client, Client)
        assert object_type in (FILE, DIRECTORY)
        if path in ('/', ''):  # pragma: no cover
            # no cover because the tests always use a test root
            root: BoxItem = client.root_folder()
            root = self._unsafe_box_object_populate(client, root)
            return root
        if use_cache:
            cached_oid = self.__cache.get_oid(path)
            if cached_oid:
                cached_type = self.__cache.get_type(path=path) or NOTKNOWN
                return self._get_box_object(client, oid=cached_oid, object_type=cached_type, strict=strict, use_cache=use_cache)
        parent, base = self.split(path)
        cached_parent_oid = None
        if use_cache:
            cached_parent_oid = self.__cache.get_oid(parent)
        parent_object: Optional[BoxFolder]
        if cached_parent_oid is not None:
            parent_object = self._get_box_object(client, oid=cached_parent_oid, object_type=DIRECTORY, strict=strict)
        else:
            parent_object = self._get_box_object(client, path=parent, object_type=DIRECTORY, strict=strict)
            if parent_object:
                self.__cache.set_oid(parent, parent_object.object_id, DIRECTORY)
        if not parent_object:
            return None
        if parent_object.object_type != 'folder':
            raise CloudFileExistsError
        collection = parent_object.item_collection
        collection_entries = list(collection['entries'])
        entry, found_type = self.__look_for_name_in_collection_entries(client, base, collection_entries, object_type,
                                                                       strict)
        if not entry:
            start = time.monotonic()
            # the next line is very slow for big folders.
            # limit=5000 speeds it up because it lowers the number of pages
            # Is there a way to confirm the non-existence of a file that doesn't involve
            # getting every item in the parent's folder? maybe limiting the fields would speed this up...
            entries = self._box_get_items(client, parent_object, parent)
            log.debug("done getting %s, %s", parent, time.monotonic() - start)
            entry, found_type = self.__look_for_name_in_collection_entries(client, base, entries, object_type, strict)
        if not entry:
            raise CloudFileNotFoundError()
        if strict and found_type != object_type:
            raise CloudFileExistsError()
        return self._get_box_object(client, oid=entry.object_id, object_type=found_type, strict=strict)

    def _unsafe_get_box_object_from_oid(self, client: Client, oid: str, object_type: OType, strict: bool) \
            -> Optional[BoxItem]:
        assert isinstance(client, Client)
        assert object_type in (FILE, DIRECTORY)
        box_object = None
        try:
            with self._api():
                if object_type == FILE:
                    box_object = client.file(file_id=oid)
                if object_type == DIRECTORY:
                    box_object = client.folder(folder_id=oid)
                if box_object:
                    box_object = self._unsafe_box_object_populate(client, box_object)
                return box_object
        except CloudFileNotFoundError:
            pass
        except (CloudFileExistsError, PermissionError):
            raise
        except Exception as e:
            log.exception(e)
            raise

        # try again with the other type
        log.debug("Trying again")
        if object_type == FILE:
            box_object = client.folder(folder_id=oid)
        if object_type == DIRECTORY:
            box_object = client.file(file_id=oid)
        box_object = self._unsafe_box_object_populate(client, box_object)  # should raise FNF if the object doesn't exists
        if strict:  # if we are here, then the object exists and retval does not comply with "strict"
            raise CloudFileExistsError()
        return box_object

    def _unsafe_get_box_object(self, client: Client, oid: str = None, path: str = None, object_type: Optional[OType] = None,
                               strict=True, use_cache=True):
        # this is unsafe because it returns an object that can hit the api outside of the guard
        # only call this function within another guard, and don't use the return value outside of that guard
        # update: the above comment is right, but we are using the return value outside of that guard
        # over and over. This needs to be refactored to be part of the _api() guard, rather than simply using the
        # _api guard
        assert isinstance(client, Client)
        assert object_type is not None
        if object_type == NOTKNOWN:
            object_type = FILE
            strict = False
        if use_cache and path and not oid:
            cached_oid = self.__cache.get_oid(path)
            if cached_oid:
                oid = cached_oid

        assert oid is not None or path is not None
        with self._api():
            if oid is not None:
                return self._unsafe_get_box_object_from_oid(client, oid, object_type, strict)  # no cache use, so no use_cache arg
            else:
                return self._unsafe_get_box_object_from_path(client, path, object_type, strict, use_cache)

    def info_oid(self, oid: str, use_cache=True) -> Optional[OInfo]:
        with self._api() as client:
            box_object = self._get_box_object(client, oid=oid, object_type=NOTKNOWN, strict=False)  # todo: get type from cache
            oinfo = self._box_get_oinfo(client, box_object, use_cache=use_cache)
            if oinfo:
                if not oinfo.path:
                    oinfo.path = self._box_get_path(client, box_object, use_cache=use_cache)
                if box_object and oinfo.path:
                    self.__box_cache_object(client, box_object, oinfo.path)
            return oinfo

    def _clear_cache(self, *, oid=None, path=None):
        if oid is None and path is None:
            path = '/'
        self.__cache.delete(oid=oid, path=path)
        self.__seen_events = {}
        self.__event_sequence = {}
        return True

    @classmethod
    def test_instance(cls):
        instance = cls.oauth_test_instance(prefix=cls.name.upper(), token_key='jwt_token')
        instance._test_event_timeout = LongPollManager.long_poll_timeout + 10  # pylint: disable=protected-access, attribute-defined-outside-init
        return instance

    def test_short_poll_only(self, short_poll_only: bool):  # pylint: disable=unused-argument, no-self-use
        self._long_poll_manager.short_poll_only = short_poll_only
        self._long_poll_manager.unblock()


__cloudsync__ = BoxProvider
