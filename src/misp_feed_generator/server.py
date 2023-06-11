import base64
from http.server import SimpleHTTPRequestHandler


class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Authentication Required"')
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def check_auth(self, auth):
        if auth and auth.startswith("Basic "):
            auth = auth.replace("Basic ", "")
            username, password = base64.b64decode(auth).decode("utf-8").split(":")
            if username == self.username and password == self.password:
                return True
        return False

    def do_GET(self):
        auth = self.headers.get("Authorization")
        if self.check_auth(auth):
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.do_AUTHHEAD()

    def do_POST(self):
        auth = self.headers.get("Authorization")
        if self.check_auth(auth):
            SimpleHTTPRequestHandler.do_POST(self)
        else:
            self.do_AUTHHEAD()
