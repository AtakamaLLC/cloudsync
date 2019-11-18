import threading
import logging
import time
from abc import ABC, abstractmethod
from cloudsync import Runnable
from typing import Callable


class LongPollManager(Runnable):
    long_poll_timeout = 120

    def __init__(self, short_poll: Callable[[], Generator[Event, None, None]], long_poll: Callable[Optional[int], Generator[Event, None, None]]):
        self.__requires_short_poll = threading.Event()

        self.new_events_found = False
        self._parent = parent
        self.short_poll = short_poll
        self.long_poll: Callable[Tuple[int], Generator[Event, None, None]] = long_poll

    def _short_poll(self) -> Generator[Event, None, None]:
        self.__requires_short_poll.wait()
        has_items = True
        while has_items:
            has_items = False
            for event in self.short_poll():
                has_items = True
                yield event

    def do(self):
        while True:
            try:
                self.long_poll(self.long_poll_timeout)
                self.__requires_short_poll.set()  # don't condition on long_poll(), we run if there's a timeout or event
            except Exception as e:
                logging.debug('Unhandled exception during long poll %s', e)
                time.sleep(15)

    def __call__(self, *args, **kwargs):
        yield from self._short_poll()

