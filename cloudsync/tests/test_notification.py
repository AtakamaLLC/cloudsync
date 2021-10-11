import logging
from unittest.mock import MagicMock
from cloudsync.notification import Notification, NotificationManager, NotificationType, SourceEnum
log = logging.getLogger(__name__)


def test_notification():
    handle_notification = MagicMock()
    nm = NotificationManager(evt_handler=handle_notification)
    nm.notify(Notification(SourceEnum.LOCAL, NotificationType.DISCONNECTED_ERROR, None))
    nm.do()
    handle_notification.assert_called_once()
