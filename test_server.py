#test_server.py
from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"Received POST data: {post_data.decode()}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 9999), SimpleHTTPRequestHandler)
    print("Starting test server on http://127.0.0.1:9999")
    server.serve_forever()
