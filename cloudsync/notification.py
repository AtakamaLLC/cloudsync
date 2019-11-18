import logging
import typing
import queue
import enum
from dataclasses import dataclass
from cloudsync.runnable import Runnable
from cloudsync.types import LOCAL, REMOTE
from cloudsync.exceptions import *  # pylint: disable=unused-wildcard-import,wildcard-import
log = logging.getLogger(__name__)


class NotificationType(enum.Enum):
    # These types roughly correspond to the exceptions defined in exceptions.py
    STARTED = 'started'
    CONNECTED = 'connected'
    STOPPED = 'stopped'
    FILE_NAME_ERROR = 'file_name_error'
    OUT_OF_SPACE_ERROR = 'out_of_space_error'
    DISCONNECTED_ERROR = 'disconnected_error'


class SourceEnum(enum.Enum):
    LOCAL = LOCAL
    REMOTE = REMOTE
    SYNC = 2


@dataclass
class Notification:
    source: SourceEnum  # Source of the event as defined in the SourceEnum
    ntype: NotificationType  # Type of notification as defined by the enum
    path: typing.Optional[str]  # Path to the file in question, if applicable


class NotificationManager(Runnable):
    def __init__(self, evt_handler: typing.Callable[[Notification], None]):
        self.__queue: queue.Queue = queue.Queue()
        self.__handler: typing.Callable = evt_handler

    def do(self):
        log.debug("Looking for a notification")
        e = self.__queue.get()
        try:
            log.debug("Processing a notification: %s", e)
            if e is not None:
                self.__handler(e)
            else:
                self.stopped = True
        except queue.Empty:
            pass
        except Exception:
            log.exception("Error while handling a notification: %s", e)

    def notify_from_exception(self, source: SourceEnum, e: CloudException, path: typing.Optional[str] = None):
        if isinstance(e, CloudDisconnectedError):
            self.notify(Notification(source, NotificationType.DISCONNECTED_ERROR, path))
        elif isinstance(e, CloudOutOfSpaceError):
            self.notify(Notification(source, NotificationType.OUT_OF_SPACE_ERROR, path))
        elif isinstance(e, CloudFileNameError):
            self.notify(Notification(source, NotificationType.FILE_NAME_ERROR, path))
        else:
            log.debug("Encountered a cloud exception: %s (type %s)", e, type(e))

    def notify(self, e: Notification):
        self.__queue.put(e)

    def stop(self, forever=True):
        self.__queue.put(None)
        super().stop(forever=forever)
