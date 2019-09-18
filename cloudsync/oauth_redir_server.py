import logging
import sys
import socket
import threading
import errno
from typing import Callable, Any, Optional
# from src import config
from .apiserver import ApiServer
# from src.osutil import is_windows
# from src.vapiserver import VApiClient
log = logging.getLogger(__name__)


def is_windows():
    return sys.platform in ("win32", "cygwin")


class OAuthFlowException(Exception):
    pass


class OAuthBadTokenException(Exception):
    pass


class OAuthRedirServer:
    PORT_MIN = 52400
    PORT_MAX = 52450
    GUI_TIMEOUT = 15

    def __init__(self, html_response_generator: Callable[[bool, str], str] = None):
        self.__html_response_generator = html_response_generator
        self.__on_success: Optional[Callable[[Any], None]] = None
        self.__on_failure: Optional[Callable[[str], None]] = None
        self.__api_server: Optional[ApiServer] = None
        self.__thread: Optional[threading.Thread] = None
        self.__running = False

    @property
    def running(self):
        return self.__running

    def run(self, on_success: Callable[[Any], None], on_failure: Callable[[str], None], use_predefined_ports=False):
        if self.__running:
            raise RuntimeError('OAuth server was run() twice')
        if not on_success:
            raise ValueError('A valid on_success(...) callback is required')
        if not on_failure:
            raise ValueError('A valid on_failure(...) callback is required')
        self.__on_success = on_success
        self.__on_failure = on_failure

        log.debug('Creating oauth redir server')
        self.__running = True
        if use_predefined_ports:
            # Some providers (Dropbox) don't allow us to just use localhost
            #  redirect. For these providers, we define a range of
            #  127.0.0.1:(PORT_MIN..PORT_MAX) as valid redir URLs
            for port in range(self.PORT_MIN, self.PORT_MAX):
                try:
                    if is_windows():
                        # Windows is dumb and will be weird if we just try to
                        #  connect to the port directly. Check to see if the
                        #  port is responsive before claiming it as our own
                        try:
                            socket.create_connection(('127.0.0.1', port), 0.001)
                            continue
                        except socket.timeout:
                            pass

                    log.debug('Attempting to start api server on port %d', port)
                    self.__api_server = ApiServer('127.0.0.1', port)
                    break
                except OSError:
                    pass
        else:
            self.__api_server = ApiServer('127.0.0.1', 0)
        if not self.__api_server:
            raise OSError(errno.EADDRINUSE, "Unable to open any port in range 52400-52405")

        self.__api_server.add_route('/auth/', self.auth_redir_success, content_type='text/html')
        self.__api_server.add_route('/favicon.ico', lambda x, y: "", content_type='text/html')

        self.__thread = threading.Thread(target=self.__api_server.serve_forever,
                                         daemon=True)
        self.__thread.start()
        log.info('Listening on %s', self.__api_server.uri('/auth/'))

    def auth_redir_success(self, env, info):
        log.debug('In auth_redir_success with env=%s, info=%s', env, info)
        err = ""
        if info and ('error' in info or 'error_description' in info):
            err = info['error'] if 'error' in info else \
                info['error_description'][0]
            if isinstance(err, list):
                err = err[0]
            self.__on_failure(err)
            return self.auth_failure(err)
        try:
            self.__on_success(info)
        except OAuthFlowException:
            log.warning('Got a page request when not in flow', exc_info=True)
            err = "No pending OAuth. This can happen if you refreshed this tab. "
        except Exception as e:
            log.exception('Failed to authenticate')
            err = 'Unknown error: %s' % e

        return self.auth_failure(err) if err else self.auth_success()

    def auth_success(self):
        if self.__html_response_generator:
            return self.__html_response_generator(True, '')
        return "OAuth Success"

    def auth_failure(self, msg):
        if self.__html_response_generator:
            return self.__html_response_generator(False, msg)
        return "OAuth Failure:" + msg

    def shutdown(self):
        if self.__api_server and self.__running:
            self.__api_server.shutdown()
            self.__running = False
            self.__on_success = None
            self.__on_failure = None
        self.__thread = None

    def uri(self, *args, **kwargs):
        return self.__api_server.uri(*args, **kwargs)

    def port(self):
        return self.__api_server.port()

__all__ = ['OAuthFlowException', 'OAuthBadTokenException', 'OAuthRedirServer']
