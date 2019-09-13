import queue
from threading import Lock
from collections import namedtuple
from typing import Dict, Any, Callable


class Muxer:
    Entry = namedtuple('Entry', 'genref listeners, lock')

    already: Dict[Any, Entry] = {}
    top_lock = Lock()

    def __init__(self, func, key=None, restart=False):
        self.restart = restart
        self.func: Callable = func
        self.queue: queue.Queue = queue.Queue()
        self.shutdown = False
        self.key = key or func

        with self.top_lock:
            if self.key not in self.already:
                self.already[self.key] = self.Entry([func()], [], Lock())

            ent = self.already[self.key]

        self.genref = ent.genref
        self.lock = ent.lock
        self.listeners = ent.listeners

        self.listeners.append(self)

    def __iter__(self):
        return self

    def __next__(self):
        try:
            e = self.queue.get_nowait()
        except queue.Empty:
            with self.lock:
                try:
                    e = self.queue.get_nowait()
                except queue.Empty:
                    try:
                        e = next(self.genref[0])
                        for other in self.listeners:
                            if other is not self:
                                other.queue.put(e)
                    except StopIteration:
                        if self.restart and not self.shutdown:
                            self.genref[0] = self.func()
                        raise
        return e

    def __del__(self):
        with self.top_lock:
            try:
                self.listeners.remove(self)
            except ValueError:
                pass
            if not self.listeners and self.key in self.already:
                del self.already[self.key]
