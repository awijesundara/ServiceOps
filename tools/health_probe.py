"""Private Kubernetes probes independent of Gunicorn's user-request queue."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from tools.wait_for_database import expected_heads

STATE_DIR = Path('/tmp/serviceops-gunicorn-health')


def process_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False


def workers_ready(directory=STATE_DIR):
    try:
        master = int((directory / 'master').read_text())
        return process_alive(master) and any(
            process_alive(path.name.split('-')[1]) for path in directory.glob('worker-*')
        )
    except (OSError, ValueError):
        return False


def ready(database_url, heads):
    if not workers_ready():
        return False
    if os.getenv('STORAGE_MODE') == 'ipfs':
        return True
    try:
        # Both connect and query waits are bounded independently of app pools.
        from sqlalchemy import create_engine, text
        from sqlalchemy.pool import NullPool
        from alembic.runtime.migration import MigrationContext
        options = {'connect_timeout': 2, 'options': '-c statement_timeout=2000'} if database_url.startswith('postgres') else {}
        engine = create_engine(database_url, poolclass=NullPool, connect_args=options)
        try:
            with engine.connect() as connection:
                connection.execute(text('SELECT 1'))
                return set(MigrationContext.configure(connection).get_current_heads()) == heads
        finally:
            engine.dispose()
    except Exception:
        return False


def handler(database_url, heads):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in {'/live', '/ready'}:
                self.send_error(404)
                return
            healthy = workers_ready() if self.path == '/live' else ready(database_url, heads)
            body = json.dumps({'status': 'ok' if healthy else 'unavailable'}).encode()
            self.send_response(200 if healthy else 503)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass
    return Handler


def main():
    port = int(os.environ['GUNICORN_HEALTH_PORT'])
    server = HTTPServer(('0.0.0.0', port), handler(os.getenv('DATABASE_URL', ''), expected_heads()))
    server.serve_forever()


if __name__ == '__main__':
    main()
