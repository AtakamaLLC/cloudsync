import logging
import typing
import queue
import enum
from dataclasses import dataclass
from cloudsync.runnable import Runnable
import cloudsync.types as typ
import cloudsync.exceptions as ex


log = logging.getLogger(__name__)
__all__ = ["Notification", "NotificationType", "NotificationManager"]


# pylint: disable=multiple-statements
class NotificationType(enum.Enum):
    """These types roughly correspond to the exceptions defined in exceptions.py"""
    STARTED = 'started'                             ; """Sync has started"""
    CONNECTED = 'connected'                         ; """Provider has connected"""
    STOPPED = 'stopped'                             ; """Sync engine was stopped"""
    FILE_NAME_ERROR = 'file_name_error'             ; """File name is invalid, and is being ignored"""
    OUT_OF_SPACE_ERROR = 'out_of_space_error'       ; """Sync is halted because one provider is out of space"""
    DISCONNECTED_ERROR = 'disconnected_error'       ; """Provider was disconnected"""
    NAMESPACE_ERROR = 'namespace_error'             ; """Specified namespace is invalid/unavailable (could be auth issue)"""
    ROOT_MISSING_ERROR = 'root_missing_error'       ; """Root of cloud sync is missing, and will not be created"""
    TEMPORARY_ERROR = 'temporary_error'             ; """Upload failure, or other temp error that will be retried."""


class SourceEnum(enum.Enum):
    """Local and remote, probably belongs in types.py"""
    LOCAL = typ.LOCAL
    REMOTE = typ.REMOTE
    SYNC = 2


@dataclass
class Notification:
    """Notification from cloudsync about something."""
    source: SourceEnum                              ; """Source of the event as defined in the SourceEnum"""
    ntype: NotificationType                         ; """Type of notification as defined by the enum"""
    path: typing.Optional[str]                      ; """Path to the file in question, if applicable"""
# pylint: enable=multiple-statements


class NotificationManager(Runnable):
    """Service that receives notifications in a queue, and calls a handler for each."""
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
                # None event == stop
                if not self.stopped:
                    super().stop(forever=False)
        except Exception:
            log.exception("Error while handling a notification: %s", e)

    def notify_from_exception(self, source: SourceEnum, e: ex.CloudException, path: typing.Optional[str] = None):
        """Insert notification into the queue based on exception information."""

        log.debug("notify from exception %s, %s : %s", source, repr(e), path)

        if isinstance(e, ex.CloudDisconnectedError):
            self.notify(Notification(source, NotificationType.DISCONNECTED_ERROR, path))
        elif isinstance(e, ex.CloudOutOfSpaceError):
            self.notify(Notification(source, NotificationType.OUT_OF_SPACE_ERROR, path))
        elif isinstance(e, ex.CloudFileNameError):
            self.notify(Notification(source, NotificationType.FILE_NAME_ERROR, path))
        elif isinstance(e, ex.CloudNamespaceError):
            self.notify(Notification(source, NotificationType.NAMESPACE_ERROR, path))
        elif isinstance(e, ex.CloudRootMissingError):
            self.notify(Notification(source, NotificationType.ROOT_MISSING_ERROR, path))
        elif isinstance(e, ex.CloudTemporaryError):
            self.notify(Notification(source, NotificationType.TEMPORARY_ERROR, path))
        else:
            log.debug("Encountered a cloud exception: %s (type %s)", e, type(e))

    def notify(self, e: Notification):
        """Add notification to the queue"""
        self.__queue.put(e)

    def stop(self, forever=True, wait=True):
        """Stop the server"""
        self.__queue.put(None)
        super().stop(forever=forever, wait=wait)
