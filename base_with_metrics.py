from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from hashlib import sha256
import base64

PORT = 8000
KEY = ''
FILENAME = 'lablog.txt'


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def check_basic_auth(self):
        auth_header = self.headers.get('Authorization')

        if not auth_header:
            return False

        _, encoded_credentials = auth_header.split(' ')
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':')

        if password.replace(' ', '') == KEY:
            return password.replace(' ', '')
        else:
            return False

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/':
            self.serve_content()
            return

        authcheck = self.check_basic_auth()
        if not authcheck:
            print("sending 401 Unauthorized")
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm=\"Authorization required\"')
            self.end_headers()
            self.wfile.write(b"(extremely loud buzzer noise)")
            return
        if parsed_path.path == '/editor':
            self.serve_editor(authcheck)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith('/editor'):
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            token = query_params.get('token', [None])[0]

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            post_data_dict = parse_qs(post_data)
            content = post_data_dict.get('content', [''])[0].replace('\r\n', '\n')

            expected_token = sha256(KEY.encode('utf-8')).hexdigest()
            if not token or token != expected_token:
                self.send_error(401, "Unauthorized")
                return

            with open(FILENAME, 'w') as f:
                f.write(content)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Content written to file')

    def serve_content(self):
        try:
            with open(FILENAME, "r") as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f'''
            <noscript>
                <img src="https://web.metrics.t2v.city/ingress/297254e4-f15f-42a0-b67d-596318de6ede/pixel.gif">
            </noscript>
            <script defer src="https://web.metrics.t2v.city/ingress/297254e4-f15f-42a0-b67d-596318de6ede/script.js"></script>
            <pre>{content}</pre>
            '''.encode())
        except FileNotFoundError:
            self.send_error(404, "File not found")

    def serve_editor(self, key):
        with open(FILENAME, "r") as f:
            content = f.read()
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(f'''
        <noscript>
            <img src="https://web.metrics.t2v.city/ingress/297254e4-f15f-42a0-b67d-596318de6ede/pixel.gif">
        </noscript>
        <script defer src="https://web.metrics.t2v.city/ingress/297254e4-f15f-42a0-b67d-596318de6ede/script.js"></script>
        <hr>
        <h1>Editor</h1>
        <form action="/editor?token={sha256(key.encode('utf-8')).hexdigest()}" method="post">
            <textarea name="content" rows="30" cols="50">{content}</textarea>
            <br><button type="submit">submit</button>
        </form>
        <hr>
        '''.encode())


if __name__ == "__main__":
    httpd = HTTPServer(('localhost', PORT), SimpleHTTPRequestHandler)
    print(f"Serving on port {PORT}")
    httpd.serve_forever()
