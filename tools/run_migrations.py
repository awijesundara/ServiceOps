"""Supported Kubernetes/automation entrypoint for ServiceOps migrations.

Never update ``alembic_version`` directly. Alembic owns both schema DDL and its
revision stamp in the same migration lifecycle; the application then verifies
that the database reached the repository head before this process succeeds.
"""
import os


def main():
    os.environ["AUTO_MIGRATE"] = "true"
    from sqlalchemy import create_engine
    from serviceops_core import release_tracks
    from app import create_app

    database_url=os.environ.get('DATABASE_URL')
    image=os.environ.get('SERVICEOPS_IMAGE_REFERENCE','')
    environment=os.environ.get('SERVICEOPS_ENVIRONMENT','production')
    engine=create_engine(database_url) if database_url else None
    try:
        if engine:release_tracks.check(engine,image,environment,os.environ.get('SERVICEOPS_RELEASE_OVERRIDE_REASON',''))
        create_app()
        if engine:release_tracks.record(engine,image,environment)
    finally:
        if engine:engine.dispose()
    print("ServiceOps migrations committed and verified")


if __name__ == "__main__":
    main()
