from .fixtures import MockProvider


def test_subpath():
    m = MockProvider(True, False)
    x = "c:/Users\\Hello\\world.pptx"
    y = "c:/Users/hello"

    assert m.is_subpath(y, x)
