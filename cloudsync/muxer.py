import queue
from threading import Lock
from collections import namedtuple


class Muxer():
    Entry = namedtuple('Entry', 'genref listeners, lock')

    already = {}
    top_lock = Lock()

    def __init__(self, func, restart=False):
        self.restart = restart
        self.func = func
        self.queue = queue.Queue()

        with self.top_lock:
            if func not in self.already:
                self.already[func] = self.Entry([func()], [], Lock())
            ent = self.already[func]

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
                            if not other is self:
                                other.queue.put(e)
                    except StopIteration:
                        if self.restart:
                            self.genref[0] = self.func()
                        raise
        return e

    def __del__(self):
        with self.top_lock:
            try:
                self.listeners.remove(self)
            except ValueError:
                pass
            if not self.listeners and self.func in self.already:
                del self.already[self.func]
