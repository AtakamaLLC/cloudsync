import time
import threading
import logging
from typing import Callable, Generator
from cloudsync.runnable import Runnable 
from cloudsync.event import Event
log = logging.getLogger(__name__)


class LongPollManager(Runnable):
    """
    Class for helping providers with long poll support avoid potential threading issues
    arising from long running api requests.
    """
    long_poll_timeout = 120.0

    def __init__(self, short_poll: Callable[[], Generator[Event, None, None]],
                 long_poll: Callable[[float], bool],
                 short_poll_only=False,
                 uses_cursor=False):
        self.__provider_events_pending = threading.Event()
        self.short_poll = short_poll
        self.long_poll = long_poll
        self.short_poll_only = short_poll_only
        self.min_backoff = 1.0
        self.max_backoff = 15
        self.last_set = time.monotonic()
        self.uses_cursor = uses_cursor
        self.got_events = threading.Event()
        log.debug("EVSET: set got_events")
        self.got_events.set()

    def __call__(self) -> Generator[Event, None, None]:
        log.debug("waiting for events")
        if not self.short_poll_only:
            self.__provider_events_pending.wait()
            log.debug("done waiting for events")
            self.__provider_events_pending.clear()
        has_items = True
        while has_items:
            has_items = False
            log.debug("about to short poll")
            generator = self.short_poll()
            if generator is not None:
                for event in self.short_poll():
                    log.debug("short poll returned an event, yielding %s", event)
                    has_items = True
                    yield event
        log.debug("EVSET: set got_events")
        self.got_events.set()

    def unblock(self):
        # clear all events... let stuff loop around once
        # usually done in response to rewinding the cursor, for tests
        self.__provider_events_pending.set()
        self.got_events.set()
        self.last_set = time.monotonic()

    def done(self):
        self.unblock()

    def do(self):  # this is really "do_once"
        if self.short_poll_only:
            self.__provider_events_pending.set()
            self.interruptable_sleep(1)
        else:
            try:
                log.debug("about to long poll")
                # care should be taken to return "true" on timeouts for providers, like box that don't use cursors
                if self.uses_cursor:
                    log.debug("wait for got_events")
                    self.got_events.wait(timeout=self.long_poll_timeout)
                    if self.stopped:
                        return
                self.got_events.clear()
                assert not self.got_events.is_set()

                # if a cursor is not used, we never trust the results
                if self.long_poll(self.long_poll_timeout) or not self.uses_cursor:
                    log.debug("LPSET: long poll finished, about to check events")
                    self.__provider_events_pending.set()
                    self.last_set = time.monotonic()
                    log.debug("events check complete")
                else:
                    log.debug("long poll finished, not checking events")

            except Exception as e:
                if self.last_set and (time.monotonic() > (self.last_set + self.long_poll_timeout)):
                    # if we're getting exceptions from long_poll, still trigger a short poll after timeout seconds
                    log.debug("LPSET: long poll exceptions, about to check events")
                    self.__provider_events_pending.set()
                    self.last_set = time.monotonic()
                log.exception('Unhandled exception during long poll %s', e)
                Runnable.backoff()

    def stop(self, forever=True, wait=False):
        # Don't wait for do() to finish, could wait for up to long_poll_timeout seconds
        self.unblock()
        super().stop(forever=forever, wait=wait)
