from typing import Optional
from types import GeneratorType
import pytest
import contextlib
import time
import logging
from inspect import isgeneratorfunction

from cloudsync import CloudException, CloudTemporaryError, CloudDisconnectedError
# from cloudsync.tests.test_provider import ProviderTestMixin

log = logging.getLogger(__name__)

EXPECTED_EXCEPTIONS = set()


@contextlib.contextmanager
def provider_raises(expected_exception):
    """
    Wrapper for pytest.raises that disables the retry code for provider methods. Use this for CloudTemporaryErrors
    and CloudDisconnectedErrors, which are the ones that get retried. Other Exceptions, this method won't make a
    difference.
    """
    assert issubclass(expected_exception, BaseException)
    global EXPECTED_EXCEPTIONS
    EXPECTED_EXCEPTIONS.add(expected_exception)
    with pytest.raises(expected_exception):
        yield None
    EXPECTED_EXCEPTIONS.remove(expected_exception)


def retry_wrapper_factory(func):
    count = 4

    def wrapped(prov, *args, **kwargs):
        ex: Optional[CloudException] = None
        mult = 1.0
        for i in range(count):
            if i > 0:
                log.warning("retry %s after %s", func.__name__, repr(ex))
            try:
                retval = func(prov, *args, **kwargs)
                if isinstance(retval, GeneratorType):
                    yield from retval
                    return
                else:
                    yield retval
                    return
            except CloudTemporaryError as e:
                if type(e) in EXPECTED_EXCEPTIONS:
                    log.info("api won't retry: exception was expected %s: %s", func, repr(e))
                    raise
                ex = e
            except CloudDisconnectedError as e:
                if type(e) in EXPECTED_EXCEPTIONS:
                    log.info("api won't retry: exception was expected %s: %s", func, repr(e))
                    raise
                prov.reconnect()
                ex = e
            time.sleep(mult * (prov._test_event_timeout / 5))
            mult = mult * 1.4
        raise ex
    return wrapped


def wrap_retry(func):
    def generator_to_function_converter(prov, *args, **kwargs):
        inner_wrapper = retry_wrapper_factory(func)
        return next(inner_wrapper(prov, *args, **kwargs))
    if isgeneratorfunction(func):
        return retry_wrapper_factory(func)
    else:
        return generator_to_function_converter


