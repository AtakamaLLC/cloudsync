import re
import json
import traceback
import time

import urllib.parse as urlparse
import threading
import logging
from enum import Enum
from typing import Callable, Dict

import unittest

# TODO: this is an inappropriate default server, default should be wsgiref builtin
import waitress

# TODO: caller should specify the mechanism for channel empty detection
from waitress.channel import HTTPChannel

log = logging.getLogger(__name__)

class ApiServerLogLevel(Enum):
    NONE = 0  # do not log calls
    CALLS = 1  # log calls but not their args
    ARGS = 2  # log calls with args


class ApiError(Exception):
    def __init__(self, code, msg=None, desc=None):
        super().__init__()
        self.code = code
        self.msg = str(msg) or "UNKNOWN"
        self.desc = desc

    def __str__(self):
        return f"{self.code}, {self.msg}"

    @classmethod
    def from_json(cls, error_json):
        return cls(error_json.get('code', 500), msg=error_json.get('msg', None), desc=error_json.get('desc', None))


def api_route(path):
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
    def __init__(self, addr, port, headers=None, log_level=ApiServerLogLevel.ARGS):
        """
        Create a new server on address, port.  Port can be zero.

        from apiserver import ApiServer, ApiError, api_route

        Create your handlers by inheriting from ApiServer and tagging them with @api_route("/path").

        Alternately you can use the ApiServer() directly, and call add_handler("path", function)

        Raise errors by raising ApiError(code, message, description=None)

        Return responses by simply returning a dict() or str() object

        Parameter to handlers is a dict()

        Query arguments are shoved into the dict via urllib.parse_qs

        """
        self.__addr = addr
        self.__port = port
        self.__headers = headers if headers else []
        self.__log_level = log_level

        self.__server = waitress.server.create_server(self, host=self.__addr, port=self.__port, clear_untrusted_proxy_headers=False)

        self.__started = False
        self.__routes: Dict[str, Callable] = {}
        self.__shutting_down = False
        self.__shutdown_lock = threading.Lock()

        # routed methods map into handler
        for meth in type(self).__dict__.values():
            if hasattr(meth, "_routes"):
                for route in meth._routes:      # pylint: disable=protected-access
                    self.add_route(route, meth)

    def add_route(self, path, meth, content_type='application/json'):
        self.__routes[path] = (meth, content_type)

    def port(self):
        """Get my port"""
        sa = self.__server.socket.getsockname()
        return sa[1]

    def address(self):
        """Get my ip address"""
        sa = self.__server.socket.getsockname()
        return sa[0]

    def uri(self, path):
        """Make a URI pointing at myself"""
        if path[0] == "/":
            path = path[1:]
        uri = "http://" + self.__addr + ":" + str(self.port()) + "/" + path
        return uri

    def serve_forever(self):
        self.__started = True
        try:
            self.__server.run()
        except OSError:
            pass

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        try:
            if self.__started:
                with self.__shutdown_lock:
                    if not self.__shutting_down:
                        self.__shutting_down = True
                        timeout = time.time() + 2
                        channel: HTTPChannel
                        for channel in list(self.__server.active_channels.values()):  # Convert to a list to make a copy
                            while channel.total_outbufs_len > 0 and time.time() < timeout:
                                time.sleep(.01)  # give any connections with a non-empty output buffer a chance to drain
                        self.__server.socket.close()
                        self.__server.asyncore.close_all()
        except Exception:
            log.exception("exception during shutdown")

    def __call__(self, env, start_response):  # pylint: disable=too-many-locals, too-many-branches, too-many-statements
        with self.__shutdown_lock:
            if self.__shutting_down:
                raise ConnectionAbortedError('Cannot handle request while shutting down')
            content = b"{}"
            length = env.get("CONTENT_LENGTH", 0)
            if length:
                content = env['wsgi.input'].read(int(length))
            if content:
                try:
                    info = json.loads(content)
                except Exception:
                    raise ApiError(400, "Invalid JSON " + str(content, "utf-8"))
            else:
                info = {}

            url = '<unknown>'
            try:
                url = env.get('PATH_INFO', '/')

                if self.__log_level == ApiServerLogLevel.CALLS or self.__log_level == ApiServerLogLevel.ARGS:
                    log.debug('Processing URL %s', url)

                handler_tmp = self.__routes.get(url)
                if not handler_tmp:
                    if url[-1] == "/":
                        tmp = url[0:-1]
                        handler_tmp = self.__routes.get(tmp)
                    if not handler_tmp:
                        m = re.match(r"(.*?/)[^/]+$", url)
                        if m:
                            # adding a route "/" handles /foo
                            # adding a route "/foo/bar/" handles /foo/bar/baz
                            handler_tmp = self.__routes.get(m[1])

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
                        raise ApiError(500, type(e).__name__ + " : " + str(e), traceback.format_exc())
                else:
                    raise ApiError(404, f"No handler for {url}")
            except ApiError as e:
                try:
                    log.error("GET %s : ERROR : %s", url, e)

                    response = json.dumps({"code": e.code, "msg": e.msg, "desc": e.desc})
                    start_response(str(e.code) + ' ' + sanitize_for_status(e.msg),
                                   [('Content-Type', 'application/json'), ("Content-Length", str(len(response)))])
                    yield bytes(response, "utf-8")
                except ConnectionAbortedError as e:
                    log.error("GET %s : ERROR : %s", url, e)


class TestApiServer(unittest.TestCase):
    @staticmethod
    def test_nostart():
        httpd = ApiServer('127.0.0.1', 0)
        httpd.shutdown()

    def test_basic(self):
        class MyServer(ApiServer):
            @api_route("/popup")
            def popup(ctx, req):        # pylint: disable=no-self-argument,no-self-use
                return "HERE" + str(req)

            @api_route("/json")
            def json(ctx, req):         # pylint: disable=no-self-argument,no-self-use
                _ = req
                return {"obj": 1}

        httpd = MyServer('127.0.0.1', 0)

        httpd.add_route("/foo", lambda ctx, x: "FOO" + x["x"][0])

        try:
            print("serving on ", httpd.address(), httpd.port())

            threading.Thread(target=httpd.serve_forever, daemon=True).start()

            import requests
            response = requests.post(httpd.uri("/popup"), data='{}')
            self.assertEqual(response.text, "HERE{}")

            response = requests.post(httpd.uri("/notfound"), data='{}')
            self.assertEqual(response.status_code, 404)

            response = requests.get(httpd.uri("/foo?x=4"))
            self.assertEqual(response.text, "FOO4")
        finally:
            httpd.shutdown()

    def test_error(self):
        class MyServer(ApiServer):
            @api_route("/popup")
            def popup(ctx, unused_req):        # pylint: disable=no-self-argument,no-self-use
                raise ApiError(501, "BLAH")

        httpd = MyServer('127.0.0.1', 0)

        try:
            print("serving on ", httpd.address(), httpd.port())

            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()

            import requests
            response = requests.post(httpd.uri("/popup"), data='{}')
            self.assertEqual(response.status_code, 501)
        finally:
            httpd.shutdown()

        if thread:
            thread.join(timeout=2)
            assert not thread.is_alive()


if __name__ == "__main__":
    unittest.main()
