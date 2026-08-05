"""Persist successful backup evidence for dashboards and alerting."""
import argparse
from app import PlatformSetting, create_app, db, now


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--offsite", choices=("archived", "not-configured"), required=True)
    args = parser.parse_args()
    app = create_app()
    with app.app_context():
        values = {
            "LAST_BACKUP_AT": now().isoformat(),
            "LAST_BACKUP_MANIFEST": args.manifest,
            "LAST_BACKUP_OFFSITE_STATUS": args.offsite,
        }
        for key, value in values.items():
            row = db.session.get(PlatformSetting, key)
            if row:
                row.value = value
            else:
                db.session.add(PlatformSetting(key=key, value=value))
        db.session.commit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
