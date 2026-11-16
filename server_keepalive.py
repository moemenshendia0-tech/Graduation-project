import http.server

class KeepAliveHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

if __name__ == "__main__":
    import sys
    bind = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    server = http.server.ThreadingHTTPServer((bind, port), KeepAliveHandler)
    print(f"Serving HTTP/1.1 keep-alive on {bind}:{port}")
    server.serve_forever()
