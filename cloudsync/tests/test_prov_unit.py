import pytest


from cloudsync import Namespace, CloudNamespaceError, CloudTokenError, CloudTemporaryError, CloudFileNotFoundError, \
    CloudCursorError

from .fixtures import MockProvider
from ..providers.mock import EventFilter, MockFSObject, MockEvent


def test_subpath():
    m = MockProvider(True, False)
    x = "c:/Users\\Hello\\world.pptx"
    y = "c:/Users/hello"

    assert m.is_subpath(y, x)


def test_mock_misc():

    not_bool = EventFilter.PROCESS
    with pytest.raises(ValueError):
        _ = bool(not_bool)

    prov = MockProvider(False, True)
    fs = prov._mock_fs
    assert prov in fs._listeners
    fs.remove_listener(prov)
    assert prov not in fs._listeners
    prov._set_mock_fs(fs)
    assert prov in fs._listeners
    assert prov._mock_fs == fs

    prov._use_ns = False
    assert not prov.list_ns()
    with pytest.raises(CloudNamespaceError):
        prov.namespace = Namespace("id", "name")
    with pytest.raises(CloudNamespaceError):
        prov.namespace_id = "id"
    assert not prov.namespace_id

    prov._use_ns = True
    assert len(prov.list_ns()) == 2
    prov.namespace = prov.list_ns()[0]
    prov.namespace_id = prov.list_ns()[1].id

    with pytest.raises(CloudTokenError):
        prov.connect_impl(None)

    f1 = MockFSObject("/some/file", MockFSObject.FILE, False, prov._hash_func)
    prov._locked_for_test.add(f1.path)
    with pytest.raises(CloudTemporaryError):
        prov._store_object(f1)

    prov._locked_for_test.pop()
    with pytest.raises(CloudFileNotFoundError):
        prov._unstore_object(f1)

    evt1 = MockEvent(MockEvent.ACTION_CREATE, f1)
    prov._uses_cursor = False
    assert prov._translate_event(evt1, "cursor").new_cursor is None
    assert prov.current_cursor is None
    assert prov.latest_cursor is None
    with pytest.raises(CloudCursorError):
        prov.current_cursor = "cursor"  # type: ignore
    prov.current_cursor = None  # type: ignore
    assert prov.current_cursor == prov.latest_cursor

    d1 = MockFSObject("/some/dir", MockFSObject.DIR, False, prov._hash_func)
    d1.exists = False
    evt2 = MockEvent(MockEvent.ACTION_DELETE, d1)
    prov._oidless_folder_trash_events = True
    translated = prov._translate_event(evt2, "cursor")
    assert translated.oid is None
    assert translated.path == d1.path
