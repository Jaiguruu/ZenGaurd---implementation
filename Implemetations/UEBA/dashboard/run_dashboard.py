import http.server
import socketserver
import os
import sys

PORT = 3000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def run():
    try:
        with socketserver.TCPServer(("", PORT), Handler) as httpd:
            print(f"[*] ZenGuard UEBA Dashboard served at http://localhost:{PORT}")
            print(f"[*] Target API: http://localhost:8080 (Docker Compose)")
            print("[*] Press Ctrl+C to stop.")
            httpd.serve_forever()
    except OSError:
        print(f"[!] Error: Port {PORT} is already in use.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down dashboard server.")
        sys.exit(0)

if __name__ == "__main__":
    run()
