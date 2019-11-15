import logging
import sys
import socket
import threading
import errno
from typing import Callable, Any, Optional, Tuple
# from src import config
from .apiserver import ApiServer

log = logging.getLogger(__name__)

__all__ = ['OAuthRedirServer']

# todo: use https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#web-application-flow
# then provide tools to that provider-writers don't have to do much to get their app-specific oauth to work other than
# providing the resource name, auth url and any app-specific parameters

def _is_windows():
    return sys.platform in ("win32", "cygwin")

class OAuthRedirServer:        # pylint: disable=too-many-instance-attributes
    GUI_TIMEOUT = 15

    def __init__(self, *, html_generator: Callable[[bool, str], str] = None, 
            port_range: Tuple[int, int] = None, 
            host_name: str = None):
        self.__html_response_generator = html_generator
        self.__port_range = port_range

        # generally 127.0.0.1 is better than "localhost", since it cannot
        # be accidentally or malicuously overridden in a config file
        # however, some providers (Onedrive) do not allow it

        self.__host_name = host_name or "127.0.0.1"

        self.__on_success: Optional[Callable[[Any], None]] = None
        self.__on_failure: Optional[Callable[[str], None]] = None
        self.__api_server: Optional[ApiServer] = None
        self.__thread: Optional[threading.Thread] = None
        self.__running = False
        self.event = threading.Event()
        self.success_code: str = None
        self.failure_info: str = None

    @property
    def running(self):
        return self.__running

    def run(self, on_success: Callable[[Any], None], on_failure: Callable[[str], None]):
        if self.__running:
            raise RuntimeError('OAuth server was run() twice')
        self.__on_success = on_success
        self.__on_failure = on_failure

        self.success_code = None
        self.failure_info = None
        self.event.clear()
        log.debug('Creating oauth redir server')
        self.__running = True
        if self.__port_range:
            (port_min, port_max) = self.__port_range
            # Some providers (Dropbox, Onedrive) don't allow us to just use localhost
            #  redirect. For these providers, we define a range of
            #  host_name:(port_min, port_max) as valid redir URLs
            for port in range(port_min, port_max):
                try:
                    if _is_windows():
                        # Windows will be weird if we just try to
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
            raise OSError(errno.EADDRINUSE, "Unable to open any port in range %s-%s" % (port_min, (port_max)))

        self.__api_server.add_route('/', self.auth_redir_success, content_type='text/html')
        self.__api_server.add_route('/auth', self.auth_redir_success, content_type='text/html')
        self.__api_server.add_route('/favicon.ico', lambda x, y: "", content_type='text/html')

        self.__thread = threading.Thread(target=self.__api_server.serve_forever,
                                         daemon=True)
        self.__thread.start()
        log.info('Listening on %s', self.uri())

    def auth_redir_success(self, _env, info):
        err = ""
        if info and ('error' in info or 'error_description' in info):
            log.debug("auth error")
            err = info['error'] if 'error' in info else \
                info['error_description'][0]
            if isinstance(err, list):
                err = err[0]
            self.failure_info = err
            if self.__on_failure:
                self.__on_failure(err)
            return self.auth_failure(err)
        try:
            log.debug("auth success")
            self.success_code = info["code"][0]
            if self.__on_success:
                self.__on_success(info)
        except Exception as e:
            log.exception('Failed to authenticate')
            err = 'Unknown error: %s' % e
            self.failure_info = err

        return self.auth_failure(err) if err else self.auth_success()

    def auth_success(self):
        self.event.set()
        if self.__html_response_generator:
            return self.__html_response_generator(True, '')
        return "OAuth Success"

    def auth_failure(self, msg):
        self.event.set()
        if self.__html_response_generator:
            return self.__html_response_generator(False, msg)
        return "OAuth Failure:" + msg

    def shutdown(self):
        self.event.set()
        if self.__api_server and self.__running:
            try:
                self.__api_server.shutdown()
            except Exception:
                log.exception("failed to shutdown")
            self.__running = False
            self.__on_success = None
            self.__on_failure = None
        self.__thread = None

    def wait(self, timeout=None):
        self.event.wait(timeout=timeout)

    def uri(self):
        return self.__api_server.uri("/", self.__host_name)

    def port(self):
        return self.__api_server.port()

