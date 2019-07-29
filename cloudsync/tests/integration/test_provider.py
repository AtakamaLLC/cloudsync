import os
import logging
import pytest
from io import BytesIO
from unittest.mock import patch
from typing import Union

import cloudsync

from cloudsync import Event, CloudFileNotFoundError, CloudTemporaryError, CloudFileExistsError
from cloudsync.tests.fixtures.mock_provider import Provider, MockProvider
from cloudsync.runnable import time_helper

from cloudsync.providers import GDriveProvider, DropboxProvider

log = logging.getLogger(__name__)


ProviderMixin = Union[Provider, "ProviderHelper"]

class ProviderHelper:
    creds = None
    event_timeout = 20
    event_sleep = 1

    def temp_name(self: ProviderMixin, name="tmp", *, folder=None):
        fname = self.join(folder or self.sync_root, os.urandom(16).hex() + "." + name)
        return fname

    def events_poll(self: ProviderMixin, timeout=None, until=None):
        if timeout is None:
            timeout = self.event_timeout

        if timeout == 0:
            yield from self.events()
            return

        for _ in time_helper(timeout, sleep=self.event_sleep, multiply=2):
            got = False
            for e in self.events():
                yield e
                got = True
            if not until and got:
                break
            elif until and until():
                break

    def test_cleanup(self: ProviderMixin, timeout=None, until=None):
        _ = timeout  # TODO: get rid of the arguments, if we're not going to use them
        _ = until
        # remove everything in the sync_root
        info = self.info_path(self.sync_root)
        if info:
            # TODO: this is broken. Either deletion is recursive, in which case, this is unnecessary,
            #       or it isn't, and this isn't sufficient because it's not recursive
            #       plus, listdir shouldn't be returning oids
            for info in self.listdir(info.oid):
                self.delete(info.oid)

        info = self.info_path(self.sync_root)
        if info:
            self.delete(info.oid)

    def api_retry(self: ProviderMixin, func, *ar, **kw):
        # the cloud providers themselves should *not* have their own backoff logic
        # rather, they should punt rate limit and temp errors to the sync system
        # since we're not testing the sync system here, we need to make our own

        for _ in time_helper(timeout=self.event_timeout, sleep=self.event_sleep, multiply=2):
            try:
                return func(self, *ar, **kw)
            except CloudTemporaryError:
                log.info("api retry %s %s %s", func, ar, kw, stack_info=True)

@pytest.fixture(params=['gdrive', 'dropbox', 'mock'])
def cloudsync_provider(request, gdrive_creds, dropbox_creds):
    if request.param == "gdrive":
        cls = GDriveProvider
        cls.event_timeout = 60
        cls.event_sleep = 2
        cls.creds = gdrive_creds
    elif request.param == "dropbox":
        cls = DropboxProvider
        cls.event_timeout = 20
        cls.event_sleep = 2
        cls.creds = dropboxe_creds
    elif request.param == "mock":
        cls = MockProvider
        cls.creds = {}
    return cls

@pytest.fixture
def provider(cloudsync_provider):
    class ProviderMixin(cloudsync_provider, ProviderHelper):
        def __init__(self, *ar, **kw):
            ProviderHelper.__init__(self)
            cloudsync_provider.__init__(self, *ar, **kw)
        def _api(self, *ar, **kw):
            return self.api_retry(cloudsync_provider._api, *ar, **kw)

    test_root = "/" + os.urandom(16).hex()

    prov = ProviderMixin(test_root)

    assert prov.temp_name

    prov.connect(prov.creds)

    yield prov

    prov.test_cleanup()


def test_join(mock):
    assert "/a/b/c" == mock.join("a", "b", "c")
    assert "/a/c" == mock.join("a", None, "c")
    assert "/a/b/c" == mock.join("/a", "/b", "/c")
    assert "/a/c" == mock.join("a", "/", "c")


def test_connect(provider):
    assert provider.connected


def test_create_upload_download(util, provider):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    dest = provider.temp_name("dest")

    info1 = provider.create(dest, data())

    info2 = provider.upload(info1.oid, data())

    assert info1.oid == info2.oid
    assert info1.hash == info2.hash

    assert provider.exists_path(dest)

    dest = BytesIO()
    provider.download(info2.oid, dest)

    dest.seek(0)
    assert dest.getvalue() == dat


def test_rename(util, provider: ProviderMixin):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    dest = provider.temp_name("dest")
    info1 = provider.create(dest, data())
    dest2 = provider.temp_name("dest2")
    provider.rename(info1.oid, dest2)
    assert provider.exists_path(dest2)
    assert not provider.exists_path(dest)

    # test that renaming a folder renames the children
    folder_name1 = provider.temp_name()
    folder_name2 = provider.temp_name()
    file_name = os.urandom(16).hex()
    file_path1 = provider.join(folder_name1, file_name)
    file_path2 = provider.join(folder_name2, file_name)
    sub_folder_name = os.urandom(16).hex()
    sub_folder_path1 = provider.join(folder_name1, sub_folder_name)
    sub_folder_path2 = provider.join(folder_name2, sub_folder_name)
    sub_file_name = os.urandom(16).hex()
    sub_file_path1 = provider.join(sub_folder_path1, sub_file_name)
    sub_file_path2 = provider.join(sub_folder_path2, sub_file_name)

    folder_oid = provider.mkdir(folder_name1)
    sub_folder_oid = provider.mkdir(sub_folder_path1)
    file_info = provider.create(file_path1, data())
    sub_file_info = provider.create(sub_file_path1, data())

    assert provider.exists_path(file_path1)
    assert not provider.exists_path(file_path2)
    assert provider.exists_path(sub_file_path1)
    assert not provider.exists_path(sub_file_path2)
    assert provider.exists_oid(file_info.oid)
    assert provider.exists_oid(sub_file_info.oid)

    provider.rename(folder_oid, folder_name2)

    assert provider.exists_path(file_path2)
    assert not provider.exists_path(file_path1)
    assert provider.exists_path(sub_file_path2)
    assert not provider.exists_path(sub_file_path1)
    assert provider.exists_oid(file_info.oid)
    assert provider.exists_oid(sub_file_info.oid)

    assert provider.info_oid(file_info.oid).path == file_path2
    assert provider.info_oid(sub_file_info.oid).path == sub_file_path2


def test_mkdir(util, provider: ProviderMixin):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)
    dest = provider.temp_name("dest")
    provider.mkdir(dest)
    info = provider.info_path(dest)
    assert info.otype == cloudsync.DIRECTORY
    sub_f = provider.temp_name("dest", folder=dest)
    log.debug("parent = %s, sub = %s", dest, sub_f)
    with pytest.raises(CloudFileExistsError):
        provider.create(dest, data(), None)
    assert provider.exists_path(dest)
    log.debug("folder %s exists", dest)
    provider.create(sub_f, data(), None)


def test_walk(util, provider: ProviderMixin):
    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")
    info = provider.create(dest, temp, None)
    assert not provider.walked

    got_event = False
    for e in provider.walk():
        got_event = True
        if e is None:
            break
        if e.otype == cloudsync.DIRECTORY:
            continue
        assert e.oid == info.oid
        path = e.path
        if path is None:
            path = provider.info_oid(e.oid).path
        assert path == dest
        assert e.mtime
        assert e.exists

    assert provider.walked
    assert got_event


def check_event_path(event: Event, provider: ProviderMixin, target_path):
    # confirms that the path in the event matches the target_path
    # if the provider doesn't provide the path in the event, look it up by the oid in the event
    # if we can't get the path, that's OK if the file doesn't exist
    event_path = event.path
    if event_path is None:
        try:
            event_path = provider.info_oid(event.oid).path
            assert event_path == target_path
        except CloudFileNotFoundError:
            if event.exists:
                raise


def test_event_basic(util, provider: ProviderMixin):
    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")

    # just get the cursor going
    for e in provider.events_poll(timeout=min(provider.event_timeout, 1)):
        log.debug("event %s", e)

    info1 = provider.create(dest, temp, None)
    assert info1 is not None  # TODO: check info1 for more things

    received_event = None
    event_count = 0
    for e in provider.events_poll():
        log.debug("event %s", e)
        # you might get events for the root folder here or other setup stuff
        if not e.path or e.path == dest:
            event_count += 1
            received_event = e

    assert event_count == 1
    assert received_event is not None
    assert received_event.oid
    path = received_event.path
    if path is None:
        path = provider.info_oid(received_event.oid).path
    assert path == dest
    assert received_event.mtime
    assert received_event.exists
    deleted_oid = received_event.oid
    provider.delete(oid=deleted_oid)
    provider.delete(oid=deleted_oid)  # Tests that deleting a non-existing file does not raise a FNFE

    received_event = None
    event_count = 0
    for e in provider.events_poll():
        log.debug("event %s", e)
        if not e.exists or path in e.path:
            received_event = e
            event_count += 1

    assert event_count == 1
    assert received_event is not None
    assert received_event.oid
    assert not received_event.exists
    if received_event.path is not None:
        assert received_event.path == dest
    assert received_event.oid == deleted_oid
    assert received_event.mtime


def test_event_del_create(util, provider: ProviderMixin):
    temp = BytesIO(os.urandom(32))
    temp2 = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")

    # just get the cursor going
    for e in provider.events_poll(timeout=min(provider.event_timeout, 2)):
        log.debug("event %s", e)

    info1 = provider.create(dest, temp)
    provider.delete(info1.oid)
    provider.create(dest, temp2)

    last_event = None
    saw_delete = False
    done = False
    for e in provider.events_poll(provider.event_timeout * 2, until=lambda: done):
        log.debug("event %s", e)
        # you might get events for the root folder here or other setup stuff
        path = e.path
        if not e.path:
            info = provider.info_oid(e.oid)
            if info:
                path = info.path

        if path == dest or e.exists is False:
            last_event = e 

            if e.exists is True and saw_delete:
                log.debug("done, we saw the delete and got a create after")
                done = True

            if e.exists is False:
                saw_delete = True

    # the important thing is that we always get a create after the delete event
    assert last_event
    assert last_event.exists is True


def test_api_failure(provider):
    # assert that the cloud
    # a) uses an api function
    # b) does not trap CloudTemporaryError's

    def side_effect(*a, **k):
        if a or k:
            pass
        raise CloudTemporaryError("fake disconnect")

    with patch.object(provider, "_api", side_effect=side_effect):
        with pytest.raises(CloudTemporaryError):
            provider.exists_path("/notexists")


def test_file_not_found(provider: ProviderMixin):
    # Test that operations on nonexistent file system objects raise CloudFileNotFoundError
    # when appropriate, and don't when inappropriate
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    test_file_deleted_path = provider.temp_name("dest1")  # Created, then deleted
    test_file_deleted_info = provider.create(test_file_deleted_path, data(), None)
    test_file_deleted_oid = test_file_deleted_info.oid
    provider.delete(test_file_deleted_oid)

    test_folder_deleted_path = provider.temp_name("dest1")  # Created, then deleted
    test_folder_deleted_oid = provider.mkdir(test_folder_deleted_path)
    provider.delete(test_folder_deleted_oid)

    test_path_made_up = provider.temp_name("dest2")  # Never created
    test_oid_made_up = "never created"
    # TODO: consider mocking info_path to always return None, and then call all the provider methods
    #  to see if they are handling the None, and not raising exceptions other than FNF

    # Tests:
    #   exists_path
    #       deleted file, returns false, does not raise
    #       deleted folder, returns false, does not raise
    #       never existed fsobj, returns false, does not raise
    assert provider.exists_path(test_file_deleted_path) is False
    assert provider.exists_path(test_folder_deleted_path) is False
    assert provider.exists_path(test_path_made_up) is False

    #   exists_oid
    #       deleted file, returns false, does not raise
    #       deleted folder, returns false, does not raise
    #       never existed fsobj, returns false, does not raise
    assert provider.exists_oid(test_file_deleted_oid) is False
    assert provider.exists_oid(test_folder_deleted_oid) is False
    assert provider.exists_oid(test_oid_made_up) is False

    #   info_path
    #       deleted file returns None
    #       deleted folder returns None
    #       never existed fsobj returns None
    assert provider.info_path(test_file_deleted_path) is None
    assert provider.info_path(test_folder_deleted_path) is None
    assert provider.info_path(test_path_made_up) is None

    #   info_oid
    #       deleted file returns None
    #       deleted folder returns None
    #       never existed fsobj returns None
    assert provider.info_oid(test_file_deleted_oid) is None
    assert provider.info_oid(test_folder_deleted_oid) is None
    assert provider.info_oid(test_oid_made_up) is None

    #   hash_oid
    #       deleted file returns None
    #       never existed file returns None
    # if getattr(provider, "hash_oid", False): # TODO implement hash_oid in gdrive, then don't have this be conditional
    #     assert provider.hash_oid(test_file_deleted_oid) is None
    #     assert provider.hash_oid(test_oid_made_up) is None

    #   upload
    #       to a deleted file raises FNF, or untrashes the file, either is OK
    #       to a made up oid raises FNF
    # TODO: uploading to a deleted file might not raise an FNF, it might just untrash the file
    try:
        provider.upload(test_file_deleted_oid, data(), None)
        assert provider.exists_path(test_file_deleted_path) is True
        re_delete = True
    except CloudFileNotFoundError:
        re_delete = False
        pass
    if re_delete:
        provider.delete(test_file_deleted_oid)

    with pytest.raises(CloudFileNotFoundError):
        provider.upload(test_oid_made_up, data(), None)

    #   create
    #       to a non-existent folder, raises FNF
    #       to a previously deleted folder, raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.create(test_path_made_up + "/junk", data(), None)
    with pytest.raises(CloudFileNotFoundError):
        provider.create(test_folder_deleted_path + "/junk", data(), None)

    #   download
    #       on a deleted oid raises FNF
    #       on a made up oid raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.download(test_file_deleted_oid, data())
    with pytest.raises(CloudFileNotFoundError):
        provider.download(test_oid_made_up, data())

    #   rename
    #       from a deleted oid raises FNF
    #       from a made up oid raises FNF
    #       to a non-existent folder raises [something], conditionally
    #       to a previously deleted folder raises
    #       check the rename source to see if there are others
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_file_deleted_oid, test_file_deleted_path)
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_folder_deleted_oid, test_folder_deleted_path)
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_oid_made_up, test_path_made_up)

    #   mkdir
    #       to a non-existent folder raises FNF
    #       to a previously deleted folder as parent folder raises FNF
    #       to a previously deleted file as parent folder raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.mkdir(test_path_made_up + "/junk")
    with pytest.raises(CloudFileNotFoundError):
        provider.mkdir(test_folder_deleted_path + "/junk")
    with pytest.raises(CloudFileNotFoundError):
        provider.mkdir(test_file_deleted_path + "/junk")

    #   delete
    #       on a deleted file oid does not raise
    #       on a deleted folder oid does not raise
    #       on a made up oid does not raise
    provider.delete(test_file_deleted_oid)
    provider.delete(test_folder_deleted_oid)
    provider.delete(test_oid_made_up)

    #   listdir
    #       on a deleted file raises FNF
    #       on a deleted folder raises FNF
    #       on a made up path raises FNF
    with pytest.raises(CloudFileNotFoundError):
        list(provider.listdir(test_file_deleted_oid))
    with pytest.raises(CloudFileNotFoundError):
        list(provider.listdir(test_folder_deleted_oid))
    with pytest.raises(CloudFileNotFoundError):
        list(provider.listdir(test_oid_made_up))

    # TODO: Google drive raises FNF when it can't find the root... can we test for that here?


def test_file_exists(provider: ProviderMixin):
    dat = os.urandom(32)

    def data(da=dat):
        return BytesIO(da)

    def create_and_delete_file():
        create_and_delete_file_name = provider.temp_name()
        file_info = provider.create(create_and_delete_file_name, data(), None)
        provider.delete(file_info.oid)
        return create_and_delete_file_name, file_info.oid

    def create_and_delete_folder():
        create_and_delete_folder_name = provider.temp_name()
        create_and_delete_folder_oid = provider.mkdir(create_and_delete_folder_name)
        provider.delete(create_and_delete_folder_oid)
        return create_and_delete_folder_name, create_and_delete_folder_oid

    def create_and_rename_file():
        file_name1 = provider.temp_name()
        file_name2 = provider.temp_name()
        assert file_name1 != file_name2
        file_info1 = provider.create(file_name1, data(), None)
        provider.rename(file_info1.oid, file_name2)
        return file_name1, file_info1.oid

    def create_and_rename_folder():
        folder_name1 = provider.temp_name()
        folder_name2 = provider.temp_name()
        assert folder_name1 != folder_name2
        folder_oid1 = provider.mkdir(folder_name1)
        provider.rename(folder_oid1, folder_name2)
        return folder_name1, folder_oid1

    def create_file(create_file_name=None):
        if create_file_name is None:
            create_file_name = provider.temp_name()
        file_info = provider.create(create_file_name, data(), None)
        return create_file_name, file_info.oid

    def create_folder(create_folder_name=None):
        if create_folder_name is None:
            create_folder_name = provider.temp_name()
        create_folder_oid = provider.mkdir(create_folder_name)
        return create_folder_name, create_folder_oid

    # Test that operations on existent file system objects raise CloudExistsError
    # when appropriate, and don't when inappropriate
    # api methods to check for FileExists:
    #   vulnerable to existing paths:
    #       mkdir, create, rename
    #   Possible issues to potentially check each of the vulnerable api methods:
    #       target path has a component in the parent folder that already exists as a file
    #       target path exists
    #       target path exists, but the type of the existing object at that location is different from expected
    #       target path exists, but the type of the existing object at that location is what was expected
    #       target path existed, but was deleted, different type as source
    #       target path existed, but was deleted, same type as source
    #       target path existed, but was renamed, different type as source
    #       target path existed, but was renamed, same type as source
    #
    #   vulnerable to existing OIDs:
    #       upload, delete
    #   Possible issues to potentially check each of the vulnerable api methods:
    #       target OID exists, but the type of the existing object at that location is different from expected
    #       target OID existed, but was trashed, should un-trash the object
    #       target OID is a non-empty folder, delete should raise FEx
    #

    # The enumerated tests:
    #   mkdir: where target path has a parent folder that already exists as a file, raises FEx
    name, _ = create_file()
    with pytest.raises(CloudFileExistsError):
        provider.mkdir(name + "/junk")

    #   mkdir: where target path exists as a file, raises FEx
    name, _ = create_file()
    with pytest.raises(CloudFileExistsError):
        provider.mkdir(name)

    #   mkdir: where target path exists as a folder, does not raise
    name1, oid1 = create_folder()
    oid2 = provider.mkdir(name1)
    assert oid1 == oid2

    #   mkdir: creating a file, deleting it, then creating a folder at the same path, should not raise an FEx
    name1, oid1 = create_and_delete_file()
    oid2 = provider.mkdir(name1)
    assert oid1 != oid2

    #   mkdir: creating a folder, deleting it, then creating a folder at the same path, should not raise an FEx
    name1, oid1 = create_and_delete_folder()
    oid2 = provider.mkdir(name1)
    assert oid1 != oid2

    #   mkdir: target path existed as file, but was renamed
    name1, oid1 = create_and_rename_file()
    _, oid2 = create_folder(name1)
    assert oid1 != oid2

    #   mkdir: target path existed as folder, but was renamed
    name1, oid1 = create_and_rename_folder()
    _, oid2 = create_folder(name1)
    assert oid1 != oid2

    #   upload: where target OID is a folder, raises FEx
    _, oid = create_folder()
    with pytest.raises(CloudFileExistsError):
        provider.upload(oid, data(), None)

    #   create: where target path exists, raises FEx
    name, _ = create_file()
    with pytest.raises(CloudFileExistsError):
        create_file(name)

    #   create: creating a file, deleting it, then creating a file at the same path, should not raise an FEx
    name1, oid1 = create_and_delete_file()
    _, oid2 = create_file(name1)
    assert oid1 != oid2

    #   create: creating a folder, deleting it, then creating a file at the same path, should not raise an FEx
    name1, oid1 = create_and_delete_folder()
    _, oid2 = create_file(name1)
    assert oid1 != oid2

    #   create: where target path has a parent folder that already exists as a file, raises FEx
    name, _ = create_file()
    with pytest.raises(CloudFileExistsError):
        create_file(name + "/junk")

    #   create: target path existed as folder, but was renamed
    name, _ = create_and_rename_folder()
    create_file(name)

    #   create: target path existed as file, but was renamed
    name, _ = create_and_rename_file()
    create_file(name)

    #   rename: rename folder over empty folder succeeds
    name1, oid1 = create_folder()
    create_file(name1 + "/junk")
    name2, oid2 = create_folder()
    assert oid1 != oid2
    contents1 = [x.name for x in provider.listdir(oid1)]
    provider.rename(oid1, name2)
    assert provider.exists_oid(oid1)
    assert not provider.exists_oid(oid2)
    contents2 = [x.name for x in provider.listdir(oid1)]
    assert contents1 == contents2  # pytest MAGIC!

    #   rename: rename folder over non-empty folder raises FEx
    _, oid1 = create_folder()
    name2, oid2 = create_folder()
    assert oid1 != oid2
    create_file(name2 + "/junk")
    with pytest.raises(CloudFileExistsError):
        provider.rename(oid1, name2)

    #   rename: target has a parent folder that already exists as a file, raises FEx
    folder_name, _ = create_file()  # notice that I am creating a file, and calling it a folder
    with pytest.raises(CloudFileExistsError):
        create_file(folder_name + "/junk")

    #   rename: renaming file over empty folder, raises FEx
    folder_name, folder_oid = create_folder()
    file_name, file_oid = create_file()
    with pytest.raises(CloudFileExistsError):
        provider.rename(file_oid, folder_name)

    #   rename: renaming file over non-empty folder, raises FEx
    create_file(folder_name + "/test")
    with pytest.raises(CloudFileExistsError):
        provider.rename(file_oid, folder_name)  # reuse the same file and folder from the last test

    #   rename: renaming a folder over a file, raises FEx
    with pytest.raises(CloudFileExistsError):
        provider.rename(folder_oid, file_name)  # reuse the same file and folder from the last test

    #   rename: create a file, delete it, then rename a file to the same path as the deleted, does not raise
    deleted_file_name, deleted_file_oid = create_and_delete_file()
    name2, oid2 = create_file()
    provider.rename(oid2, deleted_file_name)

    #   rename: create a folder, delete it, then rename file to the same path as the deleted, does not raise
    deleted_folder_name, deleted_folder_oid1 = create_and_delete_folder()
    name2, oid2 = create_file()
    provider.rename(oid2, deleted_folder_name)

    #   rename: create a file, delete it, then rename a folder to the same path as the deleted, does not raise
    deleted_file_name, deleted_file_oid = create_and_delete_file()
    name2, oid2 = create_folder()
    provider.rename(oid2, deleted_file_name)

    #   rename: create a folder, delete it, then rename folder to the same path as the deleted, does not raise
    deleted_folder_name, deleted_folder_oid1 = create_and_delete_folder()
    name2, oid2 = create_folder()
    provider.rename(oid2, deleted_folder_name)

    #   rename: target folder path existed, but was renamed away, folder type as source
    name1, oid1 = create_and_rename_folder()
    name2, oid2 = create_folder()
    provider.rename(oid2, name1)

    #   rename: target folder path existed, but was renamed away, file type as source
    name1, oid1 = create_folder()
    name2, oid2 = create_file()
    temp = provider.temp_name()
    provider.rename(oid1, temp)
    provider.rename(oid2, name1)

    #   rename: target file path existed, but was renamed away, folder type as source
    name1, oid1 = create_file()
    name2, oid2 = create_folder()
    temp = provider.temp_name()
    provider.rename(oid1, temp)
    provider.rename(oid2, name1)

    #   rename: target file path existed, but was renamed away, file type as source
    name1, oid1 = create_file()
    name2, oid2 = create_file()
    temp = provider.temp_name()
    provider.rename(oid1, temp)
    provider.rename(oid2, name1)


# TODO: test that renaming A over B replaces B's OID with A's OID, and B's OID is trashed


def test_listdir(provider: ProviderMixin):
    outer = provider.temp_name()
    root = provider.dirname(outer)
    temp_name = provider.is_subpath(root, outer)
    outer_oid = provider.mkdir(outer)
    assert provider.exists_path(outer)
    assert provider.exists_oid(outer_oid)
    inner = outer + temp_name
    inner_oid = provider.mkdir(inner)
    assert provider.exists_oid(inner_oid)
    provider.create(outer + "/file1", BytesIO(b"hello"))
    provider.create(outer + "/file2", BytesIO(b"there"))
    provider.create(inner + "/file3", BytesIO(b"world"))
    contents = [x.name for x in provider.listdir(outer_oid)]
    assert len(contents) == 3
    expected = ["file1", "file2", temp_name[1:]]
    assert contents.sort() == expected.sort()
