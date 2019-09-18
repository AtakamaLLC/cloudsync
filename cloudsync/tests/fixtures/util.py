from typing import NamedTuple
from inspect import getframeinfo, stack
import logging
from cloudsync.provider import Provider
from cloudsync import SyncManager, CloudFileNotFoundError

log = logging.getLogger(__name__)

log.setLevel(logging.INFO)

TIMEOUT = 4

class WaitFor(NamedTuple):
    side: int = None
    path: str = None
    hash: bytes = None
    oid: str = None
    exists: bool = True

class RunUntilHelper:
    def run_until_found(self: SyncManager, *files, timeout=TIMEOUT):
        log.debug("running until found")
        last_error = None

        def found():
            ok = True

            for info in files:
                if type(info) is tuple:
                    info = WaitFor(side=info[0], path=info[1])

                try:
                    other_info = self.providers[info.side].info_path(info.path)
                except CloudFileNotFoundError:
                    other_info = None

                if other_info is None:
                    nonlocal last_error
                    if info.exists is False:
                        log.debug("waiting not exists %s", info.path)
                        continue
                    log.debug("waiting exists %s", info.path)
                    last_error = CloudFileNotFoundError(info.path)
                    ok = False
                    break

                if info.exists is False:
                    ok = False
                    break

                if info.hash and info.hash != other_info.hash:
                    log.debug("waiting hash %s", info.path)
                    ok = False
                    break

            return ok

        self.run(timeout=timeout, until=found)

        if not found():
            if last_error:
                raise TimeoutError("timed out while waiting: %s" % last_error)
            else:
                raise TimeoutError("timed out while waiting")

