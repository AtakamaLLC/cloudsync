import threading
import logging
import json
import webbrowser
import hashlib
import time
import arrow
import requests

from typing import Optional, Generator, Union, Dict, Tuple

from boxsdk import Client, JWTAuth, OAuth2
from boxsdk.object.item import Item as box_item
from boxsdk.object.folder import Folder as box_folder
from boxsdk.object.file import File as box_file
from boxsdk.object.event import Event as box_event
from boxsdk.exception import BoxException, BoxAPIException  # , BoxAPIException, BoxNetworkException, BoxOAuthException
from boxsdk.session.session import Session, AuthorizedSession

from cloudsync.hierarchical_cache import HierarchicalCache
from cloudsync.utils import debug_args
from cloudsync import Provider, OInfo, DIRECTORY, FILE, NOTKNOWN, Event, DirInfo, OType

from cloudsync.oauth import OAuthConfig, OAuthToken

from cloudsync.exceptions import CloudTokenError, CloudDisconnectedError, CloudFileNotFoundError, \
    CloudFileExistsError, CloudException, CloudCursorError
from cloudsync import Provider, OInfo, Hash, DirInfo, Cursor, Event, LongPollManager

log = logging.getLogger(__name__)
logging.getLogger('boxsdk.network.default_network').setLevel(logging.ERROR)
logging.getLogger('urllib3.connectionpool').setLevel(logging.INFO)

# TODO:
#   refactor _api to produce the client or a box_object, or consider if I want to switch to the RESTful api instead
#   add caching for the object id's and types

# Dox:
#   sdk:
#       https://github.com/box/box-python-sdk
#       https://github.com/box/box-python-sdk/blob/master/docs/usage
#       https://box-python-sdk.readthedocs.io/en/stable/index.html
#   api:
#      https://developer.box.com/en/reference/


# noinspection PyProtectedMember
class BoxProvider(Provider):  # pylint: disable=too-many-instance-attributes, too-many-public-methods
    additional_invalid_characters = ''
    events_to_track = ['ITEM_COPY', 'ITEM_CREATE', 'ITEM_MODIFY', 'ITEM_MOVE', 'ITEM_RENAME', 'ITEM_TRASH',
                       'ITEM_UNDELETE_VIA_TRASH', 'ITEM_UPLOAD']

    _auth_url = 'https://account.box.com/api/oauth2/authorize'
    _token_url = "https://api.box.com/oauth2/token"
    _scopes = []
    base_box_url = 'https://api.box.com/2.0'
    events_endpoint = '/events'
    long_poll_timeout = 120

    def __init__(self, oauth_config: Optional[OAuthConfig] = None):
        super().__init__()

        self.__cursor = None
        self.__client = None
        self.__long_poll_config = {}
        self.__long_poll_session = requests.Session()

        self.__api_key = None
        self.refresh_token = None
        self.mutex = threading.RLock()

        self._oauth_config = oauth_config
        self._long_poll_manager = LongPollManager(self.short_poll, self.long_poll, short_poll_only=True)
        self.events = self._long_poll_manager
        self._ids: Dict[str, str] = {}
        self.__seen_events = {}
        metadata_template = {"hash": str, "mtime": int, "readonly": bool, "shared": bool, "size": int}
        self.__cache = HierarchicalCache(self, 0, metadata_template)
        self.__root_id = None

    def _store_refresh_token(self, access_token, refresh_token):
        self.__creds = {"api_key": access_token,
                        "refresh_token": refresh_token,
                       }
        self._oauth_config.creds_changed(self.__creds)

    def interrupt_auth(self):
        self._oauth_config.shutdown()

    def authenticate(self):
        logging.error('authenticating')
        try:
            self._oauth_config.start_auth(self._auth_url, self._scopes)
            token = self._oauth_config.wait_auth(self._token_url, include_client_id=True)
        except Exception as e:
            log.error("oauth error %s", e)
            raise CloudTokenError(str(e))

        return {"api_key": token.access_token,
                "refresh_token": token.refresh_token,
               }

    def get_quota(self):
        with self._api() as client:
            user = client.user(user_id='me').get()

            logging.error(dir(user))

            res = {
                'used': user.space_used,
                'limit': user.space_amount,
                'login': user.login,
            }
            log.debug("quota %s", res)
            return res

    def connect(self, creds):
        log.debug('Connecting to box')
        if not self.__client:
            self.__creds = creds

            jwt_token = creds.get('jwt_token')
            api_key = creds.get('api_key')
            refresh_token = creds.get('refresh_token')

            if not jwt_token:
                if not ((self._oauth_config.app_id and self._oauth_config.app_secret) and (refresh_token or api_key)):
                    raise CloudTokenError("require app_id/secret and either api_key or refresh token")

            try:
                with self.mutex:
                    if jwt_token:
                        jwt_dict = json.loads(jwt_token)
                        sdk = JWTAuth.from_settings_dictionary(jwt_dict)
                        self.__client = Client(sdk)
                    else:
                        if not refresh_token:
                            raise CloudTokenError("Missing refresh token")
                        box_session = Session()
                        box_kwargs = box_session.get_constructor_kwargs()
                        box_oauth = OAuth2(client_id=self._oauth_config.app_id,
                                           client_secret=self._oauth_config.app_secret,
                                           access_token=self.__creds["api_key"],
                                           refresh_token=self.__creds["refresh_token"],
                                           store_tokens=self._store_refresh_token)

                        box_session = AuthorizedSession(box_oauth, **box_kwargs)
                        self.__client = Client(box_oauth, box_session)
                with self._api() as client:
                    self.connection_id = client.user(user_id='me').get().id
                    self.__api_key = sdk.access_token
                    self._long_poll_manager.start()
            except BoxException:
                log.exception("Error during connect")
                self.disconnect()
                raise CloudTokenError()

    def disconnect(self):
        self._long_poll_manager.stop()
        self.__client = None
        self.connection_id = None

    def reconnect(self):
        if not self.connected:
            self.connect(self.__creds)

    # noinspection PyMethodParameters
    class Guard:
        def __init__(self, client, box):
            self.__client = client
            self.__box = box

        def __enter__(self) -> Client:
            self.__box.mutex.__enter__()
            return self.__client

        def __exit__(self, ty, ex, tb):
            self.__box.mutex.__exit__(ty, ex, tb)

            if ex:
                try:
                    raise ex
                except (TimeoutError,):
                    self.__box.disconnect()
                    raise CloudDisconnectedError("disconnected on timeout")
                except BoxAPIException as e:
                    if e.status == 400 and e.code == 'folder_not_empty':
                        raise CloudFileExistsError()
                    elif e.status == 404 and e.code == 'not_found':
                        raise CloudFileNotFoundError()
                    elif e.status == 404 and e.code == 'trashed':
                        raise CloudFileNotFoundError()
                    elif e.status == 409 and e.code == 'item_name_in_use':
                        raise CloudFileExistsError()
                    else:
                        log.exception("unknown box exception: \n%s", e)
                except CloudException:
                    raise
                except Exception as e:
                    pass

    def _api(self, *args, **kwargs) -> Guard:
        needs_client = kwargs.get('needs_client', None)
        if needs_client and not self.__client:
            raise CloudDisconnectedError("currently disconnected")
        return self.Guard(self.__client, self)

    @property
    def name(self):
        return 'box'

    @property
    def latest_cursor(self):
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
        self.__cursor = val

    def long_poll(self, timeout=long_poll_timeout):
        log.debug("inside long_poll")
        try:
            if self.__long_poll_config.get('retries_remaining', 0) < 1:
                log.debug("creds = %s", self.__creds)
                headers = {'Authorization': 'Bearer %s' % (self.__api_key, )}
                log.debug("headers: %s", headers)
                srv_resp = self.__long_poll_session.options(self.base_box_url + self.events_endpoint,
                                                            headers=headers)
                log.debug("response content is %s, %s", srv_resp.status_code, srv_resp.content)
                if not (200 <= srv_resp.status_code < 300):
                    raise CloudTokenError
                server_json = srv_resp.json().get('entries')[0]
                self.__long_poll_config = {
                    "url": server_json.get('url'),
                    "retries_remaining": int(server_json.get('max_retries')),
                    "retry_timeout": int(server_json.get('retry_timeout'))
                }
            srv_resp: requests.Response = self.__long_poll_session.get(self.__long_poll_config.get('url'),
                                                    timeout=timeout)  # long poll
            srv_resp_dict = srv_resp.json()
            log.debug("server message is %s", srv_resp_dict.get('message'))
            return srv_resp_dict.get('message') == 'new_change'
        except requests.exceptions.ReadTimeout:  # need new long poll server:
            log.debug('Timeout during long poll')
            return False
        # TODO except boxerror.too_many_retries (or whatever the exception is called)
        finally:
            self.__long_poll_config['retries_remaining'] = self.__long_poll_config.get('retries_remaining', 1) - 1

    def events(self) -> Generator[Event, None, None]:
        pass

    def short_poll(self) -> Generator[Event, None, None]:
        # see: https://developer.box.com/en/reference/resources/realtime-servers/
        log.debug("inside short_poll() cursor = %s", self.current_cursor)
        with self._api() as client:
            response = client.events().get_events(limit=100, stream_position=self.current_cursor)
            new_position = response.get('next_stream_position')
            for change in (i for i in response.get('entries') if i.get('event_type')):
                if self.__seen_events.get(change.event_id):
                    # log.debug("skipped duplicate event %s", change.event_id)
                    continue
                change: box_event
                log.debug("got event %s %s", change.event_id, self.__cursor)
                log.debug("event type is %s", change.get('event_type'))
                self.__seen_events[change.event_id] = time.monotonic()
                ts = arrow.get(change.get('created_at')).float_timestamp
                change_source = change.get('source')
                if isinstance(change_source, box_item):
                    otype = DIRECTORY if type(change_source) is box_folder else FILE
                    oid = change_source.id
                    path = self._box_get_path(change_source)
                    ohash = change_source.sha1 if type(change_source) is box_file else None
                    exists = change_source.item_status == 'active'
                else:
                    log.debug("ignoring event type %s source type %s", change.get('event_type'), type(change_source))
                    continue

                event = Event(otype, oid, path, ohash, exists, ts, new_cursor=new_position)

                old_path = self.__cache.get_path(oid)
                old_type = self.__cache.get_type(oid=oid)
                if (path and old_path != path) or old_type == DIRECTORY:
                    self.__cache.delete(path=path)

                yield event

            if new_position:  # todo: do we want to raise if we don't have a new position?
                self.current_cursor = new_position

    # noinspection DuplicatedCode
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

    def upload(self, oid, file_like, metadata=None) -> OInfo:
        with self._api():
            box_object: box_file = self._get_box_object(oid=oid, object_type=FILE, strict=False)
            if box_object is None:
                raise CloudFileNotFoundError()
            if box_object.object_type != 'file':
                raise CloudFileExistsError()
            new_object = box_object.update_contents_with_stream(file_like)
            retval = self._box_get_oinfo(new_object)
            return retval

    def create(self, path, file_like, metadata=None) -> OInfo:
        with self._api():
            parent, base = self.split(path)
            parent_object = self._get_box_object(path=parent, object_type=DIRECTORY)
            if parent_object is None:
                raise CloudFileNotFoundError()
            # TODO: implement preflight_check on the upload_stream() call
            new_object: box_file = parent_object.upload_stream(file_stream=file_like, file_name=base)
            log.debug("caching id %s for file %s", new_object.object_id, path)
            self.__cache.create(path, new_object.object_id)
            retval = self._box_get_oinfo(new_object, parent_path=parent)
            return retval

    def download(self, oid, file_like):
        with self._api():
            box_object: box_file = self._get_box_object(oid=oid, object_type=FILE)
            if box_object is None:
                raise CloudFileNotFoundError()
            box_object.download_to(writeable_stream=file_like)

    def rename(self, oid, path) -> str:
        self.__cache.delete(path=path)
        try:
            with self._api():
                box_object: box_file = self._get_box_object(oid=oid, object_type=NOTKNOWN)  # todo: get object_type from cache
                if box_object is None:
                    self.__cache.delete(oid=oid)
                    raise CloudFileNotFoundError()
                info = self._box_get_oinfo(box_object)
                if info.path:
                    old_path = info.path
                else:
                    old_path = self._box_get_path(box_object)
                old_parent, old_base = self.split(old_path)
                new_parent, new_base = self.split(path)
                if new_parent == old_parent:
                    try:
                        with self._api():
                            retval = box_object.rename(new_base)
                    except CloudFileExistsError:
                        if box_object.object_type == 'file':
                            raise
                        # are we renaming a folder over another empty folder?
                        box_conflict = self._get_box_object(path=path, object_type=NOTKNOWN)  # todo: get type from cache
                        if box_conflict is None:  # should't happen... we just got a FEx error, and we're not moving
                            raise
                        items = self._box_get_items(box_conflict, new_parent)
                        if box_conflict.object_type == 'folder' and len(items) == 0:
                            box_conflict.delete()
                        else:
                            raise
                        return self.rename(oid, path)
                else:
                    new_parent_object = self._get_box_object(path=new_parent, object_type=DIRECTORY, strict=False)
                    if new_parent_object is None:
                        raise CloudFileNotFoundError()
                    elif new_parent_object.object_type != 'folder':
                        raise CloudFileExistsError()

                    retval = box_object.move(parent_folder=new_parent_object, name=new_base)
                self.__cache.rename(old_path, path)
                return retval.id
        except Exception:
            self.__cache.delete(oid=oid)
            raise

    def mkdir(self, path) -> str:
        log.debug("MKDIR ---------------- path=%s", path)
        try:
            with self._api() as client:
                parent, base = self.split(path)
                log.debug("MKDIR ---------------- parent=%s base=%s", parent, base)
                parent_object: box_folder = self._get_box_object(path=parent, object_type=DIRECTORY)
                if parent_object is None:
                    raise CloudFileNotFoundError()
                child_object: box_folder = parent_object.create_subfolder(base)
                self.__cache.mkdir(path, child_object.object_id)
                log.debug("MKDIR ---------------- path=%s oid=%s", path, child_object.object_id)

                return child_object.object_id
        except CloudFileExistsError as e:
            self.__cache.delete(path=path)
            try:
                box_object = self._get_box_object(path=path, object_type=DIRECTORY, strict=False)
            except Exception:
                raise e
            if box_object is None or box_object.object_type != 'folder':
                raise
            else:
                return box_object.object_id
        except Exception:
            self.__cache.delete(path=path)
            raise

    def rmtree(self, oid):
        with self._api():
            box_object = self._get_box_object(oid=oid, object_type=DIRECTORY, strict=False)  # todo: get type from cache
            if box_object is None:
                return
            if box_object.object_type == 'file':
                box_object.delete()
            else:
                box_object.delete(recursive=True)
        self.__cache.delete(oid=oid)

    def delete(self, oid):
        with self._api():
            box_object = self._get_box_object(oid=oid, object_type=NOTKNOWN)  # todo: get type from cache
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
            with self._api():
                box_object = self._get_box_object(oid=oid, object_type=NOTKNOWN)  # NOTKNOWN because it's not cached
                if box_object is None:
                    return False
                box_object.get()
                return True
        except CloudFileNotFoundError:
            return False

    def exists_path(self, path) -> bool:
        if self.__cache.get_type(path=path):
            return True
        return self.info_path(path) is not None

    def _box_get_items(self, box_object, path):
        with self._api():
            if box_object._item_type == 'file':
                return []
            # entries = list(box_object.get_items(limit=5000, fields=['type', 'id', 'name', 'sha1']))
            entries = list(box_object.get_items(limit=5000))
            if not path:
                path = self._box_get_path(box_object)
            self._cache_collection_entries(entries, path)
            return entries

    def listdir(self, oid) -> Generator[DirInfo, None, None]:
        # optionally takes a path, to make creating the OInfo cheaper, so that it doesn't need to figure out the path
        with self._api() as client:
            parent_object = self._get_box_object(oid=oid, object_type=DIRECTORY)
            if parent_object is None:
                raise CloudFileNotFoundError()
            parent_path = self._box_get_path(parent_object)

            # shitty attempt 1 that fails due to caching in the sdk:
            # entries = parent_object.item_collection['entries']  # don't use this, new children may be missing

            # shitty attempt 2 that fails due to caching in the sdk:
            # entries = self._box_get_items(parent_object, parent_path)
            # for entry in entries:
            #     if type(entry) is dict:  # Apparently, get_box_object by path returns dicts and by oid returns objects?
            #         raise NotImplementedError
            #         # retval = self._box_get_dirinfo_from_collection_entry(entry)
            #     else:
            #         retval = self._box_get_dirinfo(entry, parent_path)
            #     if retval is not None:
            #         yield retval

            # attempt 3 that (hopefully) avoids those issues, and gets newly created items
            # see https://github.com/box/box-python-sdk#making-api-calls-manually
            url = parent_object.get_url('items')
            log.debug("url = %s", url)
            json_response = client.make_request('GET', url).json()
            log.debug("json resp = %s", json_response)
            for entry in json_response['entries']:
                log.debug("entry = %s", entry)
                collection_entry = self._box_get_dirinfo_from_collection_entry(entry, parent_path)
                log.debug("collection_entry = %s", collection_entry)
                yield collection_entry

    def hash_data(self, file_like) -> Hash:
        # get a hash from a filelike that's the same as the hash i natively use
        sha1 = hashlib.sha1()
        for c in iter(lambda: file_like.read(32768), b''):
            sha1.update(c)
        return sha1.hexdigest()

    def _box_object_is_root(self, box_object: box_item):
        with self._api() as client:
            if not box_object:
                return False
            if box_object._item_type == 'file':
                return False
            if self.__root_id is None:
                self.__root_id = client.root_folder().object_id
            object_is_root = (box_object.object_id == self.__root_id)
            return object_is_root

    def _box_get_path(self, box_object: box_item, use_cache=True) -> Optional[str]:
        with self._api():
            if self._box_object_is_root(box_object):
                return self.sep
            if use_cache:
                cached_path = self.__cache.get_path(box_object.object_id)
                if cached_path:
                    return cached_path
            path_collection = None
            if hasattr(box_object, 'path_collection'):
                path_collection = box_object.path_collection
            if path_collection is not None:
                return self._get_path_from_collection(path_collection, box_object.name)
            else:
                raise NotImplementedError("oid is %s" % (box_object.object_id, ))  # should this be path="", or maybe do the box_object.get(), or some other thing?

    def _get_path_from_collection(self, path_collection: dict, base_name: str):
        retval_list = []
        entries = path_collection['entries']
        for entry in entries:
            if entry.id != '0':
                retval_list.append(entry.name)
        if base_name:
            retval_list.append(base_name)
        return self.join(retval_list)

    def _box_get_dirinfo(self, box_object: Union[box_file, box_folder], parent_path=None) -> Optional[DirInfo]:
        with self._api():
            oinfo = self._box_get_oinfo(box_object, parent_path)
            if not oinfo.path:
                oinfo.path = self._box_get_path(box_object)
            if oinfo:
                retval = DirInfo(otype=oinfo.otype, oid=oinfo.oid, hash=oinfo.hash, path=oinfo.path, name=box_object.name,
                                 size=0, mtime=None, shared=False, readonly=False)
                # TODO: get the size, mtime, shared and readonly from the box_object
                return retval
            return None

    def _box_get_oinfo(self, box_object: Union[box_file, box_folder], parent_path=None, use_cache=True) -> Optional[OInfo]:
        if box_object is None:
            return None

        with self._api():
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
        with self._api():
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
        if path == "/" or path == '':
            with self._api() as client:
                return self._box_get_oinfo(client.root_folder().get())

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

        log.debug("getting box object for %s:%s", cached_oid, path)
        box_object = self._get_box_object(oid=cached_oid, path=path, object_type=cached_type or NOTKNOWN, strict=False)
        log.debug("got box object for %s:%s %s", cached_oid, path, box_object)
        parent, _ = self.split(path)
        _, dir_info = self.__box_cache_object(box_object)
        log.debug("dirinfo = %s", dir_info)

        if dir_info:
            return OInfo(dir_info.otype, dir_info.oid, dir_info.hash, dir_info.path, dir_info.size)
        return None

    def _get_box_object(self, oid=None, path=None, object_type: OType = None, strict=True) -> Optional[Union[box_folder, box_file]]:
        assert object_type is not None
        with self._api():
            try:
                unsafe_box_object = self._unsafe_get_box_object(oid=oid, path=path, object_type=object_type, strict=strict)
                retval = unsafe_box_object
                return retval
            except CloudFileNotFoundError:
                return None
            except CloudFileExistsError:
                raise

    def __look_for_name_in_collection_entries(self, name, collection_entries, object_type, strict):
        for entry in collection_entries:
            entry: box_item
            if entry.name == name:
                found_type = DIRECTORY if entry.object_type == 'folder' else FILE
                if object_type is not OType.NOTKNOWN and found_type != object_type and strict:
                    raise CloudFileExistsError()
                return self._get_box_object(oid=entry.object_id, object_type=found_type, strict=strict), found_type
        return None, None

    def __box_get_metadata(self, box_object, path=None):
        with self._api():
            path = path or self._box_get_path(box_object)
            parent = None
            if path:
                parent, _ = self.split(path)
            dir_info = self._box_get_dirinfo(box_object, parent_path=parent)
            if dir_info:
                metadata = {"size": dir_info.size}
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

    def _cache_collection_entries(self, entries, parent_path):
        for entry in entries:
            self.__box_cache_object(entry, self.join(parent_path, entry.name))

    def __box_cache_object(self, box_object: box_folder, path=None) -> Tuple[Optional[Dict], Optional[DirInfo]]:
        with self._api():
            if not box_object:
                if path:
                    self.__cache.delete(path=path)
                return None, None
            path = path or self._box_get_path(box_object)
            otype = FILE if box_object._item_type == 'file' else DIRECTORY
            metadata, dir_info = self.__box_get_metadata(box_object, path)
            # Do we need to check if we have metadata here? The current code should always return metadata if we have
            # a box_object, which we know we do because of the check above. If we don't get metadata here, we should
            # clear the cache for the current oid, and return right away.

            self.__cache.update(path, otype, box_object._object_id, metadata, keep=True)

            if otype == FILE:
                return metadata, dir_info

            if hasattr(box_object, "item_collection"):
                for child in box_object.item_collection.get('entries', []):
                    assert path
                    child_path = self.join(path, child.name)
                    child_otype = FILE if child._item_type == 'file' else DIRECTORY
                    self.__cache.update(child_path, child_otype, child._object_id, keep=True)

            return metadata, dir_info

    def _unsafe_get_box_object(self, oid=None, path=None, object_type: OType = None, strict=True):
        # this is unsafe because it returns an object that can hit the api outside of the guard
        # only call this function within another guard, and don't use the return value outside of that guard
        # update: the above comment is right, but we are using the return value outside of that guard
        # over and over. This needs to be refactored to be part of the _api() guard, rather than simply using the
        # _api guard
        assert object_type is not None
        if object_type == NOTKNOWN:
            object_type = FILE
            strict = False
        if path and not oid:
            cached_oid = self.__cache.get_oid(path)
            if cached_oid:
                oid = cached_oid

        assert oid is not None or path is not None
        box_object = None
        with self._api() as client:
            if oid is not None:
                try:
                    with self._api():
                        if object_type == FILE:
                            box_object = client.file(file_id=oid)
                        if object_type == DIRECTORY:
                            box_object = client.folder(folder_id=oid)
                        get = box_object.get()
                        return get
                except CloudFileNotFoundError:
                    pass
                except CloudFileExistsError:
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
                retval = box_object.get()
                if strict and retval:
                    raise CloudFileExistsError()
                return retval
            else:
                if path == '/' or path == '':
                    root: box_folder = client.root_folder()
                    root2 = root.get()
                    return root2
                # if self.__cache.get_oid(path):
                #     return self._get_box_object(oid=entry.object_id, object_type=found_type, strict=strict)

                parent, base = self.split(path)
                cached_parent_oid = self.__cache.get_oid(parent)
                if cached_parent_oid is not None:
                    parent_object: box_folder = self._get_box_object(oid=cached_parent_oid, object_type=DIRECTORY)
                else:
                    parent_object: box_folder = self._get_box_object(path=parent, object_type=DIRECTORY)
                    if parent_object:
                        self.__cache.set_oid(parent, parent_object.object_id, DIRECTORY)
                if not parent_object:
                    return None
                if parent_object.object_type != 'folder':
                    raise CloudFileExistsError
                collection = parent_object.item_collection
                collection_entries = list(collection['entries'])
                entry, found_type = self.__look_for_name_in_collection_entries(base, collection_entries, object_type, strict)
                if not entry:
                    start = time.monotonic()
                    # the next line is very slow for big folders.
                    # limit=5000 speeds it up because it lowers the number of pages
                    # Is there a way to confirm the non-existence of a file that doesn't involve
                    # getting every item in the parent's folder? maybe limiting the fields would speed this up...
                    entries = self._box_get_items(parent_object, parent)
                    log.debug("done getting %s, %s", parent, time.monotonic() - start)
                    entry, found_type = self.__look_for_name_in_collection_entries(base, collection_entries, object_type, strict)
                if not entry:
                    raise CloudFileNotFoundError()
                if strict and found_type != object_type:
                    raise CloudFileExistsError()
                return self._get_box_object(oid=entry.object_id, object_type=found_type, strict=strict)

    def info_oid(self, oid, use_cache=True) -> Optional[OInfo]:
        with self._api():
            box_object = self._get_box_object(oid=oid, object_type=NOTKNOWN)  # todo: get type from cache
            oinfo = self._box_get_oinfo(box_object, use_cache=use_cache)
            if oinfo:
                if not oinfo.path:
                    oinfo.path = self._box_get_path(box_object, use_cache=use_cache)
                if box_object and oinfo.path:
                    self.__box_cache_object(box_object, oinfo.path)
            return oinfo

    def get_parent_id(self, path):
        if not path:
            return None
        parent, _ = self.split(path)
        if parent == path:
            return self.__cache.get_oid(parent)
        parent_info = self.info_path(parent)
        if not parent_info:
            raise CloudFileNotFoundError("parent %s must exist" % parent)
        return self.__cache.get_oid(parent_info.path)

    def refresh_api_key(self):
        # Use the refresh token to get a new api key and refresh token
        raise NotImplementedError

    def write_refresh_token_to_database(self):
        raise NotImplementedError

    def _clear_cache(self, *, oid=None, path=None):
        if oid is None and path is None:
            path = '/'
        self.__cache.delete(oid=oid, path=path)