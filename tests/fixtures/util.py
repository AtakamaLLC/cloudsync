import pytest
import os
import tempfile
import shutil
from inspect import getframeinfo, stack
import logging
from cloudsync.provider import Provider

log = logging.getLogger(__name__)

log.setLevel(logging.INFO)


class Util:
    def __init__(self):
        self.base = tempfile.mkdtemp(suffix=".cloudsync")
        log.debug("temp files will be in: %s", self.base)

    @staticmethod
    def get_context(level):
        caller = getframeinfo(stack()[level+1][0])
        return caller

    def temp_file(self, *, fill_bytes=None):
        # pretty names for temps
        caller = self.get_context(1)
        fn = os.path.basename(caller.filename)
        if not fn:
            fn = "unk"
        else:
            fn = os.path.splitext(fn)[0]

        func = caller.function

        name = fn + '-' + func + "." + os.urandom(16).hex()

        fp = Provider.join(self.base, name)

        if fill_bytes is not None:
            with open(fp, "wb") as f:
                f.write(os.urandom(fill_bytes))

        log.debug("temp file %s", fp)

        return fp

    def do_cleanup(self):
        shutil.rmtree(self.base)


@pytest.fixture(scope="module")
def util(request):
    # user can override at the module level or class level
    # if tehy want to look at the temp files made

    cleanup = getattr(getattr(request, "cls", None), "util_cleanup", True)
    if cleanup:
        cleanup = getattr(request.module, "util_cleanup", True)

    u = Util()

    yield u

    if cleanup:
        u.do_cleanup()


def test_util(util):
    log.setLevel(logging.DEBUG)
    f = util.temp_file(fill_bytes=32)
    assert len(open(f, "rb").read()) == 32
