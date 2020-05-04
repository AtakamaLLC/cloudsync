from typing import NamedTuple, Union, Sequence, List, cast, Any, Tuple, Callable
import time
import logging

from cloudsync.provider import Provider
from cloudsync.runnable import time_helper
from cloudsync import CloudFileNotFoundError, CloudDisconnectedError


log = logging.getLogger(__name__)

log.setLevel(logging.INFO)

TIMEOUT = 4

WaitForArg = Union[Tuple[int, str], 'WaitFor']


class WaitFor(NamedTuple):
    side: int = None
    path: str = None
    hash: bytes = None
    oid: str = None
    exists: bool = True

    @staticmethod
    def is_found(files: Sequence[WaitForArg], providers: Tuple[Provider, Provider], errs: List[str]):
        ok = True

        errs.clear()
        for f in files:
            if type(f) is tuple:
                info = WaitFor(side=f[0], path=f[1])
            else:
                info = cast(WaitFor, f)

            try:
                other_info = providers[info.side].info_path(info.path)
            except CloudFileNotFoundError:
                other_info = None
            except CloudDisconnectedError:
                other_info = None

            if other_info is None:
                if info.exists is False:
                    log.debug("waiting not exists %s", info.path)
                    continue
                log.debug("waiting exists %s", info.path)
                errs.append("file not found %s" % info.path)
                ok = False
                break

            if info.exists is False:
                errs.append("file exists %s" % info.path)
                ok = False
                break

            if info.hash and info.hash != other_info.hash:
                log.debug("waiting hash %s", info.path)
                errs.append("mismatch hash %s" % info.path)
                ok = False
                break

        return ok


class RunUntilHelper:
    def run_until_clean(self: Any, timeout=TIMEOUT):
        # self.run(until=lambda: not self.busy, timeout=1)  # older, SLIGHTLY slower version
        start = time.monotonic()
        while self.busy:
            self.do()
            if time.monotonic() - start > timeout:
                raise TimeoutError()

    def run_until_found(self: Any, *files: WaitForArg, timeout=TIMEOUT):
        log.debug("running until found")

        errs: List[str] = []
        found = lambda: WaitFor.is_found(files, self.providers, errs)

        self.run(timeout=timeout, until=found)

        if not found():
            raise TimeoutError("timed out while waiting: %s" % errs)

    def wait_until(self: Any, found: Callable, timeout=TIMEOUT):
        start = time.monotonic()
        while not found():
            time.sleep(0.1)
            if time.monotonic() - start > timeout and not found():
                raise TimeoutError("timed out while waiting")

    def wait_until_found(self: Any, *files: WaitForArg, timeout=TIMEOUT):
        log.debug("waiting until found")

        errs: List[str] = []
        found = lambda: WaitFor.is_found(files, self.providers, errs)

        try:
            self.wait_until(found)
        except TimeoutError:
            raise TimeoutError("timed out while waiting: %s" % errs)

