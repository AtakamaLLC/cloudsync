import unittest

from cloudsync import strict, StrictError

class TestStrict(unittest.TestCase):
    def test_frozen(self):
        @strict
        class Foo:
            cdef: int = 1
            idef: int

            def __init__(self):
                self.idef = 2

        with self.assertRaises(StrictError):
            x = Foo()
            x.bad = 1

        x = Foo()
        x.cdef = 2
        x.idef = 3

    def test_init_typing(self):
        with self.assertRaises(StrictError):
            @strict
            class Foo:
                def __init__(self, z):
                    pass
