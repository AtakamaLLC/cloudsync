# pylint: disable=protected-access

import inspect, itertools, functools


class StrictError(TypeError):
    pass


def strict(cls):
    cls._x_frozen = False
    cls._x_setter = getattr(cls, "__setattr__", object.__setattr__)

    def frozen_setattr(self, key, value):
        if self._x_frozen and not hasattr(self, key):
            raise StrictError("Class %s is frozen. Cannot set '%s'." % (cls.__name__, key))
        cls._x_setter(self, key, value)

    def init_decorator(func):
        info = inspect.getfullargspec(func)

        for k in itertools.chain(info.args, info.kwonlyargs):
            if k != "self" and k not in func.__annotations__:
                raise StrictError("%s missing type specifier in __init__" % k)

        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            func(self, *args, **kwargs)
            self._x_frozen = True
        return wrapper

    cls.__setattr__ = frozen_setattr
    cls.__init__ = init_decorator(cls.__init__)

    return cls
