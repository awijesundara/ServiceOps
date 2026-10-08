"""Health, metrics, status page and PWA shell routes.

Moved from app.create_app(); endpoint names are unchanged."""
import hmac
import os
import time as time_module
from datetime import datetime, timedelta
from pathlib import Path

from alembic.config import Config as AlembicConfig
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from flask import abort, jsonify, redirect, render_template, request, Response, send_from_directory, url_for
from flask_login import login_required
from sqlalchemy import func

import app as core
from app import (
    flush_request_metrics,
    align_tz,
    APP_START_MONOTONIC,
    audit_integrity_key,
    current_storage,
    display_version,
    env_bool,
    service_availability_pct,
)
from serviceops_core.web.common import _recovery_set_status
from serviceops_models import (
    ApplicationLog,
    AuditIntegrityKey,
    db,
    MajorIncidentProfile,
    now,
    PlatformSetting,
    RequestMetricTotal,
    ServiceOffering,
    ServiceOutage,
    Tenant,
    Ticket,
    User,
)
from serviceops_core.localization import tr


def register(app):
    @app.get("/status")
    def status_page_default():
        """Convenience entry point for the common self-hosted case: exactly
        one active tenant. With more than one, there's no safe anonymous
        default to pick (that would itself be a cross-tenant existence
        leak), so this asks for the specific organization's page instead."""
        active_tenants = Tenant.query.filter_by(active=True).limit(2).all()
        if len(active_tenants) == 1:
            return redirect(url_for("status_page", slug=active_tenants[0].slug))
        abort(404, description=tr("Specify an organization: /status/<organization-slug>."))

    @app.get("/status/<slug>")
    def status_page(slug):
        """Anonymous, unauthenticated public status page. Every query here is
        explicitly scoped by the tenant resolved from the URL slug (never
        tenant_context_id(), which requires an authenticated session and
        would raise for every visitor here) and every record shown is
        opt-in-published (ServiceOffering.status_page_visible,
        MajorIncidentProfile.public) -- nothing internal-only is
        reachable from this route regardless of what exists in the tenant."""
        tenant = Tenant.query.filter_by(slug=slug, active=True).first()
        if not tenant:
            abort(404)
        services = ServiceOffering.query.filter_by(
            tenant_id=tenant.id, status_page_visible=True,
        ).order_by(ServiceOffering.name).all()
        service_states = {}
        for service in services:
            open_outage = ServiceOutage.query.filter_by(
                service_offering_id=service.id, ended_at=None,
            ).first()
            if open_outage:
                state = "outage"
            elif service.status != "Operational":
                state = "degraded"
            else:
                state = "operational"
            service_states[service.id] = {
                "state": state, "uptime_pct": service_availability_pct(service.id),
            }
        overall_state = (
            "outage" if any(row["state"] == "outage" for row in service_states.values())
            else "degraded" if any(row["state"] == "degraded" for row in service_states.values())
            else "operational"
        )
        active_incidents = MajorIncidentProfile.query.join(Ticket, MajorIncidentProfile.ticket_id == Ticket.id).filter(
            Ticket.tenant_id == tenant.id, MajorIncidentProfile.public.is_(True),
            MajorIncidentProfile.status != "Resolved",
        ).order_by(MajorIncidentProfile.declared_at.desc()).all()
        history_cutoff = now() - timedelta(days=14)
        resolved_incidents = MajorIncidentProfile.query.join(Ticket, MajorIncidentProfile.ticket_id == Ticket.id).filter(
            Ticket.tenant_id == tenant.id, MajorIncidentProfile.public.is_(True),
            MajorIncidentProfile.status == "Resolved", MajorIncidentProfile.declared_at >= history_cutoff,
        ).order_by(MajorIncidentProfile.declared_at.desc()).all()
        if active_incidents and overall_state == "operational":
            overall_state = "incident"
        return render_template(
            "status_page.html", tenant=tenant, services=services, service_states=service_states,
            overall_state=overall_state, active_incidents=active_incidents,
            resolved_incidents=resolved_incidents, company_name=core.setting_value("COMPANY_NAME", tenant.name),
        )

    @app.get("/health")
    def health():
        # Found via real failure-injection testing (B-071): a DB outage
        # previously made this raise an unhandled OperationalError straight
        # into a generic 500, logged as an ERROR-level "Unhandled exception"
        # stack trace on every poll -- indistinguishable from a real bug and
        # noisy for the whole outage, since this is also the container
        # healthcheck target (see compose.yaml) polled on a short interval.
        # /ready already degrades gracefully on the same failure; this now
        # matches that pattern instead of letting Flask's default handler
        # treat a downstream outage as an application bug.
        if core.ipfs_enabled():
            try:
                current_storage().client.node_id()
                db.session.execute(db.select(func.count(User.id))).scalar()
            except Exception:
                db.session.rollback()
                return jsonify(status="unhealthy", version=display_version()), 503
            return jsonify(status="ok", version=display_version())
        try:
            db.session.execute(db.select(func.count(User.id))).scalar()
        except Exception:
            db.session.rollback()
            return jsonify(status="unhealthy", version=display_version()), 503
        return jsonify(status="ok", version=display_version())

    @app.get("/live")
    def live():
        return jsonify(status="alive")

    @app.get("/ready")
    def ready():
        checks = {}
        if core.ipfs_enabled():
            try:
                current_storage().client.node_id()
                checks["ipfs"] = {
                    "ok": True,
                    "file_index_size": len(current_storage()._file_index),
                    "table_count": len(current_storage().get_relational_state()),
                    "checkpoint_publish_pending": (
                        current_storage().checkpoint_publish_pending
                        or app.extensions["ipfs_projection"].dirty
                    ),
                }
            except Exception as error:
                checks["ipfs"] = {"ok": False, "reason": type(error).__name__}
            try:
                db.session.execute(db.text("SELECT 1"))
                checks["volatile_projection"] = {"ok": True}
            except Exception as error:
                db.session.rollback()
                checks["volatile_projection"] = {"ok": False, "reason": type(error).__name__}
            upload_folder = app.config["UPLOAD_FOLDER"]
            checks["uploads"] = {
                "ok": os.path.isdir(upload_folder) and os.access(upload_folder, os.R_OK | os.W_OK),
                "path_configured": bool(upload_folder),
            }
            overall = all(check["ok"] for check in checks.values())
            return jsonify(status="ready" if overall else "not_ready", version=display_version(), checks=checks), 200 if overall else 503
        try:
            db.session.execute(db.text("SELECT 1"))
            checks["database"] = {"ok": True}
        except Exception as error:  # readiness must report each failed prerequisite
            db.session.rollback()
            checks["database"] = {"ok": False, "reason": type(error).__name__}
        try:
            context = MigrationContext.configure(db.session.connection())
            current_heads = set(context.get_current_heads())
            config = AlembicConfig(str(Path(core.__file__).parent / "alembic.ini"))
            expected_heads = set(ScriptDirectory.from_config(config).get_heads())
            checks["migrations"] = {
                "ok": current_heads == expected_heads,
                "current": sorted(current_heads), "expected": sorted(expected_heads),
            }
        except Exception as error:
            checks["migrations"] = {"ok": False, "reason": type(error).__name__}
        try:
            tenants = Tenant.query.filter_by(active=True).all()
            for tenant in tenants:
                active_key = AuditIntegrityKey.query.filter_by(
                    tenant_id=tenant.id, active=True,
                ).order_by(AuditIntegrityKey.id.desc()).first()
                if active_key:
                    audit_integrity_key(active_key.key_id, tenant.id)
            checks["audit_encryption"] = {"ok": True, "tenants_checked": len(tenants)}
        except Exception as error:
            db.session.rollback()
            checks["audit_encryption"] = {"ok": False, "reason": type(error).__name__}
        heartbeat = db.session.get(PlatformSetting, "WORKER_LAST_HEARTBEAT") if checks["database"]["ok"] else None
        try:
            heartbeat_at = datetime.fromisoformat(heartbeat.value) if heartbeat and heartbeat.value else None
            heartbeat_age = (now() - align_tz(heartbeat_at, now())).total_seconds() if heartbeat_at else None
            checks["worker"] = {"ok": heartbeat_age is not None and heartbeat_age < 30, "age_seconds": heartbeat_age}
        except (TypeError, ValueError):
            checks["worker"] = {"ok": False, "reason": "invalid heartbeat"}
        upload_folder = app.config["UPLOAD_FOLDER"]
        checks["uploads"] = {
            "ok": os.path.isdir(upload_folder) and os.access(upload_folder, os.R_OK | os.W_OK),
            "path_configured": bool(upload_folder),
        }
        if core.object_storage_enabled():
            try:
                core.object_storage_client().head_bucket(Bucket=os.environ["OBJECT_STORAGE_BUCKET"])
                checks["object_storage"] = {"ok": True, "bucket_configured": True}
            except Exception as error:
                checks["object_storage"] = {"ok": False, "reason": type(error).__name__}
        overall = all(check["ok"] for check in checks.values())
        return jsonify(status="ready" if overall else "not_ready", version=display_version(), checks=checks), 200 if overall else 503

    @app.get("/metrics")
    def prometheus_metrics():
        if not env_bool("METRICS_ENABLED", True):
            abort(404)
        configured_token = os.getenv("METRICS_TOKEN", "").strip()
        supplied_token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if configured_token and not hmac.compare_digest(configured_token, supplied_token):
            abort(401)
        heartbeat = db.session.get(PlatformSetting, "WORKER_LAST_HEARTBEAT")
        worker_up = 0
        if heartbeat and heartbeat.value:
            try:
                worker_up = int((now() - align_tz(datetime.fromisoformat(heartbeat.value), now())) < timedelta(seconds=30))
            except (TypeError, ValueError):
                pass
        error_hour = ApplicationLog.query.filter(
            ApplicationLog.level.in_(["ERROR", "CRITICAL"]),
            ApplicationLog.created_at >= now() - timedelta(hours=1),
        ).count()
        _, _, _, backup_age = _recovery_set_status()
        lines = [
            "# HELP serviceops_up Whether the application can query its database.",
            "# TYPE serviceops_up gauge", "serviceops_up 1",
            "# HELP serviceops_info Build information.", "# TYPE serviceops_info gauge",
            f'serviceops_info{{version="{display_version()}"}} 1',
            "# HELP serviceops_worker_up Whether the worker heartbeat is fresh.",
            "# TYPE serviceops_worker_up gauge", f"serviceops_worker_up {worker_up}",
            "# HELP serviceops_application_errors_last_hour Error and critical records in the last hour.",
            "# TYPE serviceops_application_errors_last_hour gauge",
            f"serviceops_application_errors_last_hour {error_hour}",
            "# HELP serviceops_backup_age_seconds Age of the last successful recovery set, or -1 if none is recorded.",
            "# TYPE serviceops_backup_age_seconds gauge", f"serviceops_backup_age_seconds {backup_age:.0f}",
            "# HELP serviceops_process_uptime_seconds Process uptime.",
            "# TYPE serviceops_process_uptime_seconds gauge",
            f"serviceops_process_uptime_seconds {time_module.monotonic() - APP_START_MONOTONIC:.3f}",
        ]
        flush_request_metrics()  # include this worker's buffered counts
        for row in RequestMetricTotal.query.order_by(
            RequestMetricTotal.method, RequestMetricTotal.status,
        ).all():
            lines.append(
                f'serviceops_http_requests_total{{method="{row.method}",status="{row.status}"}} '
                f'{row.request_count}'
            )
            lines.append(
                f'serviceops_http_request_duration_seconds_sum{{method="{row.method}",status="{row.status}"}} '
                f'{row.duration_sum_ms / 1000:.6f}'
            )
        return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")

    @app.get("/manifest.webmanifest")
    def pwa_manifest():
        manifest = {
            "id": "/",
            "name": core.setting_value("INSTANCE_NAME", "ServiceOps"),
            "short_name": core.setting_value("INSTANCE_NAME", "ServiceOps")[:30],
            "description": "Enterprise service operations",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "background_color": "#f4f7f8",
            "theme_color": core.setting_value("BRAND_TEAL", "#003e4c"),
            "icons": [
                {"src": url_for("static", filename="icons/serviceops-icon-192.png"), "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
                {"src": url_for("static", filename="icons/serviceops-icon-512.png"), "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
            ],
        }
        response = jsonify(manifest)
        response.mimetype = "application/manifest+json"
        return response

    @app.get("/service-worker.js")
    def pwa_service_worker():
        response = send_from_directory(
            app.static_folder, "service-worker.js",
            mimetype="application/javascript", max_age=0,
        )
        response.headers["Service-Worker-Allowed"] = "/"
        return response

    @app.get("/ipfs-home")
    @login_required
    def ipfs_home():
        if not core.ipfs_enabled():
            abort(404)
        return redirect(url_for("dashboard"))

    @app.get("/branding/company-logo.png")
    def company_logo():
        path = os.path.join(app.config["UPLOAD_FOLDER"], "company-logo.png")
        if not os.path.exists(path):
            abort(404)
        return send_from_directory(app.config["UPLOAD_FOLDER"], "company-logo.png",
                                   mimetype="image/png", max_age=300)

    @app.get("/help")
    @login_required
    def help_center():
        return render_template("help.html")

    @app.get("/mobile-app")
    @login_required
    def mobile_app():
        return render_template("mobile_app.html", mobile_version="1.3.2", mobile_build="8")
