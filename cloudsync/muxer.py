import queue
from threading import Lock
from collections import namedtuple
from typing import Dict, Any, Callable


class Muxer:
    """
    Turn generators into subscribable streams

    from cloudsync.muxer import Muxer
    """
    Entry = namedtuple('Entry', 'genref listeners, lock')

    already: Dict[Any, Entry] = {}
    top_lock = Lock()

    def __init__(self, func, key=None, restart=False):
        """
        Create or subscribe to a generator function.

        Args:
            func: generator function
            key: globally unique id (default is just func)
            restart: make the generator infinite, by re-calling it forever

        Synopsis:

        ```
            x = Muxer(generator_function)
            y = Muxer(generator_function)

            # putting these loops in threads is OK

            for e in x:
                do()

            for e in y:
                do()

        ```
        """
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

    def empty(self):
        return self.queue.empty()

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
