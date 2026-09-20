"""AI routes share application authentication, CSRF, policy and audit controls."""
import json
import uuid
from datetime import timedelta
from types import SimpleNamespace

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from serviceops_models import AIConfiguration, AIMessage, AIRun, db, now, settings_cipher
from serviceops_core.ai import access, service
from serviceops_core.ai.provider import ProviderError, generate, validate_configuration
from serviceops_core.storage import ipfs_enabled

def register(app):
    blueprint = Blueprint("ai", __name__)
    from app import audit, require_action, roles

    @blueprint.route("/admin/ai", methods=["GET", "POST"])
    @roles("admin")
    @require_action("administer")
    def settings():
        service.actor(current_user)
        config = AIConfiguration.query.filter_by(tenant_id=current_user.tenant_id).with_for_update().first()
        if request.method == "POST":
            action = request.form.get("action", "save")
            if action == "disable":
                if config:
                    config.enabled = False
                    config.revision += 1
                    config.updated_by_id = current_user.id
                    service.cancel_active(current_user.tenant_id)
                audit("ai disabled", "AI configuration", "Master switch disabled")
                db.session.commit()
                flash("AI disabled. Queued work is cancelled; in-flight results will be discarded.", "success")
                return redirect(url_for("ai.settings"))
            if action == "test":
                if not config:
                    abort(400)
                from app import route_rate_limit
                if not route_rate_limit("ai_probe", f"tenant:{current_user.tenant_id}", 3):
                    db.session.commit()
                    abort(429)
                snapshot = SimpleNamespace(**{name: getattr(config, name) for name in
                    ("provider", "model", "endpoint", "key_encrypted", "external_consent", "max_output_tokens")})
                audit("ai connection test", "AI configuration", "Synthetic prompt only; no operational records")
                db.session.commit()
                try:
                    generate(snapshot, [], probe=True)
                    flash("Provider connection succeeded using a synthetic prompt.", "success")
                except ProviderError as error:
                    flash(str(error), "error")
                return redirect(url_for("ai.settings"))
            if action != "save":
                abort(400)
            if not config:
                config = AIConfiguration(tenant_id=current_user.tenant_id, revision=0, key_encrypted="")
                db.session.add(config)
            old_destination = (config.provider, config.endpoint)
            try:
                config.provider = request.form.get("provider", "self_hosted")
                config.endpoint = request.form.get("endpoint", "").strip().rstrip("/")
                config.model = request.form.get("model", "").strip()
                if len(config.endpoint) > 500 or len(config.model) > 160 or config.provider not in {"self_hosted", "openai"}:
                    raise ProviderError("Invalid provider, endpoint or model.")
                config.enabled = request.form.get("enabled") == "on"
                config.incident_enabled = request.form.get("incident_enabled") == "on"
                config.external_consent = request.form.get("external_consent") == "on"
                for name, low, high, default in (("daily_limit", 1, 1000, 100), ("max_output_tokens", 128, 4096, 1500),
                                                 ("retention_days", 1, 30, 7)):
                    value = int(request.form.get(name, default))
                    if not low <= value <= high:
                        raise ProviderError(f"{name.replace('_', ' ').capitalize()} must be between {low} and {high}.")
                    setattr(config, name, value)
                if old_destination != (config.provider, config.endpoint) or request.form.get("clear_key"):
                    config.key_encrypted = ""
                key = request.form.get("api_key", "").strip()
                if len(key) > 4096 or any(char in key for char in "\r\n"):
                    raise ProviderError("Invalid API key.")
                if key:
                    config.key_encrypted = settings_cipher().encrypt(key.encode()).decode()
                if config.enabled:
                    if ipfs_enabled():
                        raise ProviderError("AI jobs require PostgreSQL storage; IPFS mode is not supported.")
                    validate_configuration(config)
                config.revision += 1
                config.updated_by_id = current_user.id
                service.cancel_active(current_user.tenant_id)
                audit("ai configured", "AI configuration",
                      f"enabled={config.enabled}; incidents={config.incident_enabled}; provider={config.provider}; revision={config.revision}")
                db.session.commit()
                flash("AI configuration saved. Previous queued and running investigations were cancelled.", "success")
            except (ProviderError, ValueError) as error:
                db.session.rollback()
                flash(str(error) if isinstance(error, ProviderError) else "Enter valid numeric limits.", "error")
            return redirect(url_for("ai.settings"))
        return render_template("ai_settings.html", config=config, ipfs=ipfs_enabled())

    @blueprint.route("/incidents/<int:ticket_id>/ai", methods=["GET", "POST"])
    @login_required
    def incident(ticket_id):
        identity = service.actor(current_user)
        config = service.enabled_config(identity.tenant_id, lock=request.method == "POST")
        ticket = service.visible_incident(identity, ticket_id)
        if request.method == "POST":
            try:
                request_key = str(uuid.UUID(request.form.get("request_key", "")))
            except ValueError:
                abort(400, description="Refresh the page before starting an investigation.")
            existing = AIRun.query.filter_by(tenant_id=identity.tenant_id, user_id=identity.id, request_key=request_key).first()
            if existing:
                if existing.ticket_id != ticket.id:
                    abort(409)
                return redirect(url_for("ai.result", run_id=existing.id))
            try:
                validate_configuration(config)
            except ProviderError as error:
                abort(409, description=str(error))
            # Tenant configuration row lock serializes submissions and daily quota accounting.
            start = now().replace(hour=0, minute=0, second=0, microsecond=0)
            if AIRun.query.filter(AIRun.tenant_id == identity.tenant_id, AIRun.created_at >= start).count() >= config.daily_limit:
                abort(429, description="Your organization has reached its daily AI request limit.")
            if AIRun.query.filter(AIRun.tenant_id == identity.tenant_id, AIRun.user_id == identity.id,
                                  AIRun.status.in_(service.ACTIVE)).first():
                abort(409, description="You already have an AI investigation in progress.")
            run = AIRun(tenant_id=identity.tenant_id, user_id=identity.id, ticket_id=ticket.id,
                        actor_role=identity.role, config_revision=config.revision, request_key=request_key,
                        provider=config.provider, model=config.model)
            db.session.add(run)
            db.session.flush()
            audit("ai requested", run.id, "Read-only incident investigation")
            db.session.commit()
            return redirect(url_for("ai.result", run_id=run.id))
        runs = AIRun.query.filter_by(tenant_id=identity.tenant_id, user_id=identity.id, ticket_id=ticket.id).order_by(
            AIRun.created_at.desc()).limit(10).all()
        return render_template("ai_incident.html", ticket=ticket, runs=runs, request_key=str(uuid.uuid4()), config=config)

    @blueprint.route("/ai/runs/<run_id>", methods=["GET", "POST"])
    @login_required
    def result(run_id):
        identity = service.actor(current_user)
        config = service.enabled_config(identity.tenant_id)
        run = AIRun.query.filter_by(id=run_id, tenant_id=identity.tenant_id, user_id=identity.id).first_or_404()
        ticket = service.visible_incident(identity, run.ticket_id)
        if identity.role != run.actor_role:
            abort(403, description="Switch to the role used to request this investigation.")
        if request.method == "POST":
            AIRun.query.filter(AIRun.id == run.id, AIRun.status.in_(service.ACTIVE)).update(
                {"status": "cancelled", "completed_at": now()}, synchronize_session=False)
            audit("ai cancelled", run.id, "Requested by operator")
            db.session.commit()
            return redirect(url_for("ai.result", run_id=run.id))
        if run.created_at.replace(tzinfo=now().tzinfo) < now() - timedelta(days=config.retention_days):
            abort(410, description="This AI investigation has expired.")
        sources = json.loads(run.sources_json)
        if not service.sources_accessible(identity, sources):
            abort(403, description="You no longer have access to all evidence used by this investigation.")
        for source in sources:
            source["url"] = (url_for("ticket_detail", ticket_id=source["record_id"]) if source["kind"] == "ticket" else
                             url_for("knowledge_detail", article_id=source["record_id"]) if source["kind"] == "knowledge" else
                             url_for("ci_edit", ci_id=source["record_id"]))
        return render_template("ai_result.html", run=run, ticket=ticket, sources=sources)

    def authorized_run(run_id):
        """Load a run only for the person who started it, under the role they started it with."""
        run = AIRun.query.filter_by(id=run_id, tenant_id=current_user.tenant_id, user_id=current_user.id).first_or_404()
        if run.kind == "chat":
            try:
                scope = access.build_scope(current_user)
            except access.ScopeError:
                abort(403)
            config = service.enabled_config(scope.tenant_id, feature="chat")
            if scope.role != run.actor_role:
                abort(403, description="Switch to the role used for this conversation.")
            return run, config, scope
        identity = service.actor(current_user)
        config = service.enabled_config(identity.tenant_id)
        service.visible_incident(identity, run.ticket_id)
        if identity.role != run.actor_role:
            abort(403, description="Switch to the role used to request this investigation.")
        return run, config, identity

    def source_links(sources):
        for source in sources:
            source["url"] = (url_for("ticket_detail", ticket_id=source["record_id"]) if source["kind"] == "ticket" else
                             url_for("knowledge_detail", article_id=source["record_id"]) if source["kind"] == "knowledge" else
                             url_for("ci_edit", ci_id=source["record_id"]))
        return sources

    def no_store(payload, status=200):
        response = jsonify(payload)
        response.status_code = status
        response.headers["Cache-Control"] = "no-store"
        return response

    @blueprint.route("/ai/runs/<run_id>/stream")
    @login_required
    def stream(run_id):
        """Progressive output for a run. Short polling, not SSE: it works unchanged through the
        Cloudflare tunnel and never holds a web worker."""
        run, config, who = authorized_run(run_id)
        after = request.args.get("after", type=int, default=-1)
        body = {"id": run.id, "status": run.status, "seq": run.seq}
        if after == run.seq and run.status in service.ACTIVE:
            return no_store({**body, "changed": False})
        finished = run.status == "completed"
        sources = []
        if finished:
            sources = json.loads(run.sources_json)
            ok = (access.sources_still_accessible(who, sources) if run.kind == "chat"
                  else service.sources_accessible(who, sources))
            if not ok:
                abort(403, description="You no longer have access to all evidence used by this answer.")
            sources = source_links(sources)
        problem = {"failed": "The assistant could not complete this request.",
                   "cancelled": "Stopped. No answer was kept."}.get(run.status, "")
        return no_store({**body, "changed": True, "text": run.result_text if finished else run.partial_text,
                         "reasoning": run.reasoning_text if config.show_reasoning else "",
                         "steps": json.loads(run.steps_json or "[]"), "sources": sources, "error": problem,
                         "usage": json.loads(run.usage_json or "{}") if finished else {}})

    @blueprint.route("/ai/runs/<run_id>/cancel", methods=["POST"])
    @login_required
    def cancel(run_id):
        run, _, _ = authorized_run(run_id)
        AIRun.query.filter(AIRun.id == run.id, AIRun.status.in_(service.ACTIVE)).update(
            {"status": "cancelled", "completed_at": now(), "partial_text": "", "reasoning_text": "", "question": "",
             "seq": AIRun.seq + 1}, synchronize_session=False)
        if run.message_id:
            AIMessage.query.filter(AIMessage.id == run.message_id, AIMessage.status == "pending").update(
                {"status": "cancelled", "content": "", "reasoning": ""}, synchronize_session=False)
        audit("ai cancelled", run.id, "Requested by user")
        db.session.commit()
        return no_store({"id": run.id, "status": "cancelled"})

    app.register_blueprint(blueprint)
    app.jinja_env.globals["ai_available"] = service.available
