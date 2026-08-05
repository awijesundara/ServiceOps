"""Audited, guarded break-glass recovery commands.

Run through ``./serviceops recover-admin`` / ``recover-audit-key`` so a
checksummed database+uploads recovery set is captured before any mutation.
Passwords are read from stdin and never accepted as command-line arguments.
"""
import argparse
import secrets
import sys

from app import (
    AuditIntegrityKey, Tenant, User, UserSession, audit, db, now,
    settings_cipher,
)
from serviceops_core.security import hash_password


def verify_active_keys():
    failures = []
    for tenant in Tenant.query.filter_by(active=True).all():
        key = AuditIntegrityKey.query.filter_by(
            tenant_id=tenant.id, active=True,
        ).order_by(AuditIntegrityKey.id.desc()).first()
        if not key:
            failures.append(f"{tenant.slug}: no active audit key")
            continue
        try:
            settings_cipher().decrypt(key.secret_encrypted.encode())
        except Exception as error:  # operator diagnostic must name the failed prerequisite
            failures.append(f"{tenant.slug}: {type(error).__name__}")
    return failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("diagnose", "reset-admin", "recover-audit-key"))
    parser.add_argument("--username")
    parser.add_argument("--tenant")
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args()

    from app import create_app
    app = create_app()
    with app.app_context():
        failures = verify_active_keys()
        if args.action == "diagnose":
            if failures:
                print("Audit encryption readiness FAILED: " + "; ".join(failures), file=sys.stderr)
                return 2
            print("Audit encryption readiness passed for every active tenant.")
            return 0
        if not args.confirm:
            print("Refusing mutation without --confirm.", file=sys.stderr)
            return 2
        if args.action == "reset-admin":
            if failures:
                print("Refusing reset because mandatory audit keys cannot be decrypted: " + "; ".join(failures), file=sys.stderr)
                print("Recover the lost key or explicitly run recover-audit-key first.", file=sys.stderr)
                return 2
            user = User.query.filter_by(username=args.username).first()
            if not user or user.role not in {"admin", "superadmin"}:
                print("The requested administrator was not found.", file=sys.stderr)
                return 2
            password = sys.stdin.readline().rstrip("\n")
            if len(password) < 14:
                print("Password must contain at least 14 characters.", file=sys.stderr)
                return 2
            user.password_hash = hash_password(password)
            user.active = True
            user.failed_login_count = 0
            user.locked_until = None
            user.auth_version += 1
            UserSession.query.filter_by(user_id=user.id, revoked_at=None).update(
                {"revoked_at": now(), "revoked_by_id": user.id}
            )
            audit("break-glass credential reset", user.username,
                  "account unlocked; password rotated; sessions revoked",
                  user_id=user.id, tenant_id=user.tenant_id)
            db.session.commit()
            print(f"Recovered administrator {user.username}; all previous sessions were revoked.")
            return 0
        tenant = Tenant.query.filter_by(slug=args.tenant).first()
        if not tenant:
            print("Tenant not found.", file=sys.stderr)
            return 2
        old_keys = AuditIntegrityKey.query.filter_by(tenant_id=tenant.id, active=True).all()
        recovery_user = User.query.filter(
            User.tenant_id == tenant.id, User.role.in_(["admin", "superadmin"]), User.active.is_(True),
        ).order_by(User.id).first()
        if not recovery_user:
            print("No active administrator exists in this tenant to own the recovery event.", file=sys.stderr)
            return 2
        for key in old_keys:
            key.active = False
            key.retired_at = now()
        key_id = f"recovery-{now().strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
        db.session.add(AuditIntegrityKey(
            tenant_id=tenant.id, key_id=key_id, active=True,
            secret_encrypted=settings_cipher().encrypt(secrets.token_bytes(32)).decode(),
            created_by_id=recovery_user.id, activated_at=now(),
        ))
        db.session.flush()
        audit("audit recovery boundary", key_id,
              "prior active key was unreadable; historical signatures require the separately escrowed prior key",
              user_id=recovery_user.id, tenant_id=tenant.id)
        db.session.commit()
        print(f"Created audit recovery boundary {key_id} for {tenant.slug}.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
