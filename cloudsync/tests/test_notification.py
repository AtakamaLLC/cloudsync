import logging
from unittest.mock import MagicMock
from cloudsync.notification import Notification, NotificationManager, NotificationType, SourceEnum
log = logging.getLogger(__name__)


def test_notification():
    handler = MagicMock()
    nm = NotificationManager(evt_handler=handler)
    nm.notify(Notification(SourceEnum.LOCAL, NotificationType.DISCONNECTED_ERROR, None))
    nm.do()
    handler.assert_called_once()
