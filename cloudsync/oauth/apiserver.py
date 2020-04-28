"""
A threaded wsgi web server.

Very simple, no dependencies.

Exports ApiServer, ApiError and api_route
"""

import sys
import json
import traceback
import socket

from socketserver import ThreadingMixIn
from wsgiref.simple_server import make_server, WSGIRequestHandler, WSGIServer
import urllib.parse as urlparse
import threading
import logging
from enum import Enum
from typing import Callable, Dict, Tuple, Any

import unittest
import requests

log = logging.getLogger(__name__)

__all__ = ['ApiServer', 'ApiError', 'api_route']


class NoLoggingWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, unused_format, *args):        # pylint: disable=arguments-differ
        pass


class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    allow_reuse_address = True


class ThreadedWSGIServerEx(ThreadedWSGIServer):
    allow_reuse_address = False


class ApiServerLogLevel(Enum):
    NONE = 0  # do not log calls
    CALLS = 1  # log calls but not their args
    ARGS = 2  # log calls with args


class ApiError(Exception):
    """
    User can raise an ApiError in order to abort processing and return something other than '200' to the web client.

    Args:
        code: status code
        msg: message to show
        desc: description of the error
        json: json to return, instead of any error descriptions
    """
    def __init__(self, code, msg=None, desc=None, json=None):       # pylint: disable=redefined-outer-name
        super().__init__()
        self.code = code
        self.msg = str(msg) or "UNKNOWN"
        self.desc = desc
        self.json = json

    def __str__(self):
        return f"{self.code}, {self.msg}"

    @classmethod
    def from_json(cls, error_json):
        return cls(error_json.get('code', 500), msg=error_json.get('msg', None), desc=error_json.get('desc', None))


def api_route(path):
    """
    Decorator for handling specific urls.

    Args:
        path: the route to handle


    If this ends in a '/', it will handle all routes starting with that path.
    """
    def outer(func):
        if not hasattr(func, "_routes"):
            setattr(func, "_routes", [])
        func._routes += [path]
        return func
    return outer


def sanitize_for_status(e):
    e = e.replace("\r\n", " ")
    e = e.replace("\n", " ")
    e = e.replace("\r", " ")
    e = e[0:100]
    return e


class ApiServer:
    """
    from apiserver import ApiServer, ApiError, api_route

    Create your handlers by inheriting from ApiServer and tagging them with @api_route("/path").

    Alternately you can use the ApiServer() directly, and call add_handler("path", function)

    Raise errors by raising ApiError(code, message, description=None)

    Return responses by simply returning a dict() or str() object

    Parameter to handlers is a dict()

    Query arguments are shoved into the dict via urllib.parse_qs

    """
    def __init__(self, addr: str, port: int, headers=None, log_level=ApiServerLogLevel.ARGS, allow_reuse=False):
        """
        Create a new server on address, port.  Port can be zero.

        Args:
            addr: ip address
            port: port number, can be zero
            headers: dict of headers to include on every response
            log_level: how much logging to do
            allow_reuse: whether to allow port reuse
        """
        self.__addr = addr
        self.__port = port
        self.__headers = headers if headers else []
        self.__log_level = log_level

        self.__started = False
        if allow_reuse:
            server_class = ThreadedWSGIServer
        else:
            server_class = ThreadedWSGIServerEx
        self.__server = make_server(app=self, host=self.__addr, port=self.__port, handler_class=NoLoggingWSGIRequestHandler, server_class=server_class)
        self.__routes: Dict[str, Tuple[Callable, str]] = {}
        self.__shutting_down = False
        self.__shutdown_lock = threading.Lock()
        self.__server.socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self.__server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)

        # routed methods map into handler
        for fname in dir(self):
            meth = getattr(self, fname)
            if not callable(meth):
                continue
            if hasattr(meth, "_routes"):
                for route in meth._routes:      # pylint: disable=protected-access
                    self.add_route(route, meth)

        log.debug("routes %s", list(self.__routes.keys()))

    def add_route(self, path, meth, content_type='application/json'):
        """
        Add a new route handler.
        """
        self.__routes[path] = (meth, content_type)

    def port(self):
        """Get my port"""
        return self.__server.server_port

    def address(self):
        """Get my ip address"""
        return self.__server.server_name

    def uri(self, path="/", hostname=None):
        """Make a URI pointing at myself"""
        if path[0] == "/":
            path = path[1:]
        hostname = hostname or self.__addr
        uri = "http://" + hostname + ":" + str(self.port()) + "/" + path
        return uri

    def serve_forever(self):
        """Start listening and responding."""
        self.__started = True
        try:
            self.__server.serve_forever()
        except OSError:
            pass

    def __del__(self):
        if self.__started and not self.__shutting_down:
            print("note: didn't shut down oauth server", file=sys.stderr)

    def shutdown(self):
        """Stops the current server, if started"""
        try:
            if self.__started:
                with self.__shutdown_lock:
                    if not self.__shutting_down:
                        self.__shutting_down = True
                        self.__server.shutdown()
                        self.__server.server_close()
        except Exception:
            log.exception("exception during shutdown")

    def __call__(self, env, start_response):  # pylint: disable=too-many-locals, too-many-branches, too-many-statements
        with self.__shutdown_lock:
            if self.__shutting_down:
                url = env.get('PATH_INFO', '/')
                log.error("Ignoring URI hit during shutdown %s", url)
                start_response("500 Aborted", [('Content-Type', 'text/plain')])
                yield bytes("Aborted", "utf-8")
                return

            content = b"{}"
            length = env.get("CONTENT_LENGTH", 0)
            content_type = env.get('CONTENT_TYPE')
            info: Dict[str, Any] = {}
            try:
                if length:
                    content = env['wsgi.input'].read(int(length))

                if content_type.startswith('multipart/form-data'):
                    log.info("multipart form uploads not currently supported")
                elif content_type.startswith('application/x-www-form-urlencoded'):
                    info = urlparse.parse_qs(content)
                    for k in info:
                        if len(info[k]) == 1 and type(info[k]) is list:
                            info[k] = info[k][0]        # type:ignore
                else:
                    if content:
                        try:
                            info = json.loads(content)
                            if type(info) != dict:
                                info = {"content": info}
                        except Exception:
                            raise ApiError(400, "Invalid JSON " + str(content, "utf-8"))
                    else:
                        info = {}

                url = env.get('PATH_INFO', '/')

                if self.__log_level == ApiServerLogLevel.CALLS or self.__log_level == ApiServerLogLevel.ARGS:
                    log.debug('Processing URL %s', url)

                handler_tmp = self.__routes.get(url)
                if not handler_tmp:
                    if url[-1] == "/":
                        tmp = url[0:-1]
                        handler_tmp = self.__routes.get(tmp)
                    else:
                        handler_tmp = self.__routes.get(url + "/")

                if not handler_tmp:
                    sub = url
                    m = url.rfind("/")
                    while m >= 0:
                        sub = sub[0:m]
                        # adding a route "/" handles /foo
                        # adding a route "/foo/bar/" handles /foo/bar/baz/bop
                        # adding a route "/foo/bar" handles /foo/bar and /foo/bar/ only
                        handler_tmp = self.__routes.get(sub + "/")
                        if handler_tmp:
                            env['SUB_PATH'] = url[len(sub):]
                            break
                        m = sub.rfind("/")

                if not handler_tmp:
                    handler_tmp = self.__routes.get(None)

                query = env.get('QUERY_STRING')

                if query:
                    params = urlparse.parse_qs(query)
                else:
                    params = {}

                info.update(params)

                if handler_tmp:
                    handler, content_type = handler_tmp
                    try:
                        response = handler(env, info)
                        if response is None:
                            response = ""
                        if isinstance(response, dict):
                            response = json.dumps(response)
                        response = bytes(str(response), "utf-8")
                        headers = self.__headers + [('Content-Type', content_type),
                                                    ("Content-Length", str(len(response)))]
                        start_response('200 OK', headers)
                        yield response
                    except ApiError:
                        raise
                    except ConnectionAbortedError as e:
                        log.error("GET %s : ERROR : %s", url, e)
                    except Exception as e:
                        log.exception("")
                        raise ApiError(500, type(e).__name__ + " : " + str(e), traceback.format_exc())
                else:
                    raise ApiError(404, f"No handler for {url}")
            except ApiError as e:
                try:
                    log.info("GET %s : ERROR : %s", url, e)

                    if e.json:
                        response = json.dumps(e.json)
                    else:
                        response = json.dumps({"code": e.code, "msg": e.msg, "desc": e.desc})
                    start_response(str(e.code) + ' ' + sanitize_for_status(e.msg),
                                   [('Content-Type', 'application/json'), ("Content-Length", str(len(response)))])
                    yield bytes(response, "utf-8")
                except ConnectionAbortedError as e:
                    log.error("GET %s : ERROR : %s", url, e)
            except Exception as e:
                log.exception("")
                start_response("500 Internal Unhandled Exception", ['Content-Type', 'text/plain'])
                response = repr(e)
                yield bytes(response, "utf-8")


class TestApiServer(unittest.TestCase):
    """
    Built-in test cases
    """
    @staticmethod
    def test_nostart():
        """
        Test shutdown when not started
        """
        httpd = ApiServer('127.0.0.1', 0)
        httpd.shutdown()

    def test_basic(self):
        """
        Basic function tests
        """
        class MyServer(ApiServer):
            @api_route("/popup")
            def popup(self, unused_ctx, req):        # pylint: disable=no-self-use
                return "HERE" + str(req)

            @api_route("/json")
            def json(self, unused_ctx, req):         # pylint: disable=no-self-use
                _ = req
                return {"obj": 1}

        httpd = MyServer('127.0.0.1', 0)

        httpd.add_route("/foo", lambda ctx, x: "FOO" + x["x"][0])
        httpd.add_route("/sub/", lambda ctx, x: "SUB")

        try:
            print("serving on ", httpd.address(), httpd.port())

            threading.Thread(target=httpd.serve_forever, daemon=True).start()

            response = requests.post(httpd.uri("/popup"), data='{}', timeout=1)
            self.assertEqual(response.text, "HERE{}")
            self.assertEqual(response.headers["content-type"], "application/json")

            # not found 404
            response = requests.post(httpd.uri("/notfound"), data='{}', timeout=1)
            self.assertEqual(response.status_code, 404)

            # not found subs 404
            response = requests.post(httpd.uri("/foo/not"), data='{}', timeout=1)
            self.assertEqual(response.status_code, 404)

            # get string
            response = requests.get(httpd.uri("/foo?x=4"), timeout=1)
            self.assertEqual(response.text, "FOO4")

            # not found handled
            httpd.add_route(None, lambda ctx, x: "NOTFOUNDY", content_type='text/plain')
            response = requests.get(httpd.uri("sd;lfjksdfkl;j"), timeout=1)
            self.assertEqual(response.text, "NOTFOUNDY")
            self.assertEqual(response.headers["content-type"], "text/plain")

            # subs ok
            response = requests.get(httpd.uri("/sub/folder/is"), timeout=1)
            self.assertEqual(response.text, "SUB")
            response = requests.get(httpd.uri("/sub/"), timeout=1)
            self.assertEqual(response.text, "SUB")
            response = requests.get(httpd.uri("/sub"), timeout=1)
            self.assertEqual(response.text, "SUB")

        finally:
            httpd.shutdown()

    def test_error(self):
        """
        Ensure apierrors return correctly
        """
        class MyServer(ApiServer):
            @api_route("/popup")
            def popup(self, ctx, unused_req):        # pylint: disable=no-self-use
                raise ApiError(501, "BLAH")

            @api_route(None)
            def any(self, ctx, unused_req):        # pylint: disable=no-self-use
                raise ApiError(502, json={"custom": "error"})

        httpd = MyServer('127.0.0.1', 0)

        try:
            print("serving on ", httpd.address(), httpd.port())

            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()

            response = requests.post(httpd.uri("/popup"), data='{}', timeout=1)
            self.assertEqual(response.status_code, 501)

            response = requests.post(httpd.uri("/sdjkfhsjklf"), data='{}', timeout=1)
            self.assertEqual(response.status_code, 502)
            self.assertEqual(response.json(), {"custom": "error"})
        finally:
            httpd.shutdown()

        if thread:
            thread.join(timeout=2)
            assert not thread.is_alive()


if __name__ == "__main__":
    unittest.main()
