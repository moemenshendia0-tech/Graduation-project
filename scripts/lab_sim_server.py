#!/usr/bin/env python3
"""Benign lab server (simulation): HTTP on :8080 (GET/POST) and a fixed-answer DNS responder on :53."""
import socket, sys, threading, http.server

IP = sys.argv[1] if len(sys.argv) > 1 else "203.0.113.5"


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _ok(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._ok()

    def do_POST(self):
        left = int(self.headers.get("Content-Length", 0))
        while left > 0:
            chunk = self.rfile.read(min(65536, left))
            if not chunk:
                break
            left -= len(chunk)
        self._ok()

    def log_message(self, *a):
        pass


def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((IP, 53))
    while True:
        d, a = s.recvfrom(512)
        try:
            i = 12
            while d[i] != 0:
                i += d[i] + 1
            q = d[12:i + 5]
            r = (d[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q +
                 b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([203, 0, 113, 9]))
            s.sendto(r, a)
        except Exception:
            pass


threading.Thread(target=dns, daemon=True).start()
http.server.ThreadingHTTPServer((IP, 8080), H).serve_forever()
