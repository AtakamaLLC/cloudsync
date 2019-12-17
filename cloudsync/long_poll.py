import threading
import logging
from typing import Callable, Generator, Optional
from cloudsync import Runnable, Event
log = logging.getLogger(__name__)


class LongPollManager(Runnable):
    long_poll_timeout = 120

    def __init__(self, short_poll: Callable[[], Generator[Event, None, None]],
                 long_poll: Callable[[Optional[int]], Generator[Event, None, None]],
                 short_poll_only=False):
        self.__provider_events_pending = threading.Event()
        self.short_poll = short_poll
        self.long_poll = long_poll
        self.short_poll_only = short_poll_only
        self.min_backoff = 1.0
        self.max_backoff = 15

    def __call__(self) -> Generator[Event, None, None]:
        log.debug("waiting for events")
        self.__provider_events_pending.wait()
        log.debug("done waiting for events")
        self.__provider_events_pending.clear()
        has_items = True
        while has_items:
            has_items = False
            log.debug("about to short poll")
            for event in self.short_poll():
                log.debug("short poll returned an event, yielding %s", event)
                has_items = True
                yield event

    def do(self):  # this is really "do_once"
        if self.short_poll_only:
            self.__provider_events_pending.set()
            self.interruptable_sleep(1)
        else:
            try:
                log.debug("about to long poll")
                self.long_poll(self.long_poll_timeout)
                log.debug("long poll finished, about to check events")
                self.__provider_events_pending.set()  # don't condition on _long_poll(), we run if there's a timeout or event
                log.debug("events check complete")
            except Exception as e:
                log.exception('Unhandled exception during long poll %s', e)
                raise  # Let runnable do the regular backoff
