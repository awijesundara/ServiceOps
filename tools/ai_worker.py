"""Dedicated AI worker: python -m tools.ai_worker. Never runs migrations."""
import signal
import time
from pathlib import Path

from app import create_app, db
from serviceops_core.ai.service import process_one
from serviceops_core.storage import ipfs_enabled


def main():
    if ipfs_enabled():
        raise SystemExit("AI worker requires PostgreSQL storage.")
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    app = create_app()
    with app.app_context():
        while running:
            try:
                processed = process_one()
                Path("/tmp/serviceops-ai-heartbeat").touch()
            except Exception:
                # No exception text: provider/DB errors can contain sensitive parameters.
                app.logger.error("AI worker iteration failed; pending job lease will expire safely")
                db.session.rollback()
                processed = False
            finally:
                db.session.remove()
            if not processed:
                time.sleep(3)


if __name__ == "__main__":
    main()
