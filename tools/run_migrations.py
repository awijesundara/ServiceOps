"""Supported Kubernetes/automation entrypoint for ServiceOps migrations.

Never update ``alembic_version`` directly. Alembic owns both schema DDL and its
revision stamp in the same migration lifecycle; the application then verifies
that the database reached the repository head before this process succeeds.
"""
import os


def main():
    os.environ["AUTO_MIGRATE"] = "true"
    from app import create_app

    create_app()
    print("ServiceOps migrations committed and verified")


if __name__ == "__main__":
    main()
