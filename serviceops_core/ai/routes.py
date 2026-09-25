"""AI routes share application authentication, CSRF, policy and audit controls."""
import json
import random
import time
import uuid
from datetime import timedelta
from types import SimpleNamespace

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from serviceops_models import (AIAction, AIConfiguration, AIConnection, AIConversation, AIMemory, AIMessage, AIRun, Ticket, db, now,
                               settings_cipher)
from serviceops_core.ai import access, discovery_tokens, memory, quota, routing, service
from serviceops_core.ai.provider import (PROVIDERS, ProviderError, decrypt_key, generate, list_models, normalize_endpoint,
                                         validate_configuration)
from serviceops_core.proxy_tunnel import parse_proxy_url
from serviceops_core.storage import ipfs_enabled

def register(app):
    blueprint = Blueprint("ai", __name__)
    from app import audit, require_action, roles

    def service_payload(row, counts, usage=None, calls=None):
        try:
            caps = json.loads(row.capabilities_json or "{}")
        except ValueError:
            caps = {}
        if not row.enabled:
            status = "off"
        elif row.last_test_ok is False or routing.circuit_open(row):
            status = "failing"
        elif row.last_test_ok or row.last_success_at:
            status = "ready"
        else:
            status = "untested"
        return {"id": row.id, "name": row.name, "provider": row.provider, "endpoint": row.endpoint, "model": row.model,
                "external": row.external, "enabled": bool(row.enabled), "priority": row.priority, "weight": row.weight,
                "max_concurrency": row.max_concurrency, "has_key": bool(row.key_encrypted), "status": status,
                "proxy_mode": getattr(row, "proxy_mode", "default"),
                "has_proxy": bool(getattr(row, "proxy_url_encrypted", "")),
                "load": counts.get(row.id, 0), "context": caps.get("context_tokens"),
                "today": (usage or {}).get(row.id, {"requests": 0, "tokens": 0}),
                "limits": {"rpm": row.rpm_limit, "tpm": row.tpm_limit, "rpd": row.rpd_limit, "tz": row.quota_tz or "UTC"},
                "tier": quota.tier_of(row.model), "allowance": allowance_of(row, calls),
                "preset": quota.preset_for(row.provider, row.endpoint, row.model),
                "tested_at": row.last_test_at.isoformat() if row.last_test_at else None}

    def allowance_of(row, calls):
        if calls is None or all(v is None for v in (row.rpm_limit, row.tpm_limit, row.rpd_limit)):
            return None
        head = quota.headroom(row, calls)
        return {"ok": head.ok, "reason": head.reason, "rpm_used": head.rpm_used, "tpm_used": head.tpm_used,
                "rpd_used": head.rpd_used, "resets_in": head.resets_in, "wait": head.wait}

    def clamp(value, low, high, default):
        try:
            return max(low, min(high, int(value)))
        except (TypeError, ValueError):
            return default

    def save_service(config, data, row=None):
        """Create or change one AI service from validated input. Raises ProviderError with a display-safe message."""
        creating = row is None
        provider = str(data.get("provider", row.provider if row else "self_hosted"))
        if provider not in PROVIDERS:
            raise ProviderError("Choose a supported provider.")
        endpoint = normalize_endpoint(str(data.get("endpoint", row.endpoint if row else ""))[:500]) if provider in {
            "self_hosted", "openai_compatible"} else ""
        model = str(data.get("model", row.model if row else "")).strip()[:160]
        name = " ".join(str(data.get("name", row.name if row else "")).split())[:80] or model[:80] or "AI service"
        clash = AIConnection.query.filter(AIConnection.tenant_id == current_user.tenant_id, AIConnection.name == name)
        if row is not None:
            clash = clash.filter(AIConnection.id != row.id)
        if clash.first():
            raise ProviderError("Another AI service already uses that name.")
        old_destination = (row.provider, row.endpoint) if row else None
        key_encrypted = row.key_encrypted if row else ""
        if old_destination != (provider, endpoint) and not creating or data.get("clear_key"):
            key_encrypted = ""
        typed = str(data.get("api_key", "")).strip()
        if len(typed) > 4096 or any(char in typed for char in "\r\n"):
            raise ProviderError("Invalid API key.")
        if typed:
            key_encrypted = settings_cipher().encrypt(typed.encode()).decode()
        proxy_mode = str(data.get("proxy_mode", getattr(row, "proxy_mode", "default") if row else "default"))
        if proxy_mode not in {"default", "none", "custom"}:
            raise ProviderError("Choose a supported proxy option.")
        proxy_url_encrypted = getattr(row, "proxy_url_encrypted", "") if row else ""
        typed_proxy = str(data.get("proxy_url", "")).strip()
        if len(typed_proxy) > 2048 or any(char in typed_proxy for char in "\r\n"):
            raise ProviderError("Invalid proxy URL.")
        if proxy_mode == "custom":
            if typed_proxy:
                try:
                    parse_proxy_url(typed_proxy)
                except ValueError as error:
                    raise ProviderError(str(error)) from None
                proxy_url_encrypted = settings_cipher().encrypt(typed_proxy.encode()).decode()
            elif not proxy_url_encrypted:
                raise ProviderError("Enter the custom proxy URL.")
        else:
            proxy_url_encrypted = ""
        from app import setting_value
        resolved_proxy = typed_proxy if proxy_mode == "custom" else ""
        if proxy_mode == "custom" and not resolved_proxy and proxy_url_encrypted:
            try:
                resolved_proxy = settings_cipher().decrypt(proxy_url_encrypted.encode()).decode()
            except Exception:
                raise ProviderError("AI proxy credential could not be decrypted.") from None
        candidate = SimpleNamespace(provider=provider, endpoint=endpoint, model=model, key_encrypted=key_encrypted,
                                    external_consent=True, max_output_tokens=config.max_output_tokens,
                                    proxy_mode=proxy_mode, proxy_url=resolved_proxy,
                                    default_proxy_url=setting_value("OUTBOUND_PROXY_URL", ""))
        validate_configuration(candidate)  # structure only; whether external use is permitted is decided per request
        capabilities = row.capabilities_json if row else "{}"
        token = str(data.get("discovery_token", ""))
        if token:
            capabilities = json.dumps(discovery_tokens.verify(token, candidate, decrypt_key(candidate), current_user.tenant_id,
                                                              current_user.id))
        elif row is not None and (old_destination != (provider, endpoint) or row.model != model or row.key_encrypted != key_encrypted):
            capabilities = "{}"
        if creating:
            row = AIConnection(tenant_id=current_user.tenant_id)
            db.session.add(row)
        row.name, row.provider, row.endpoint, row.model, row.key_encrypted = name, provider, endpoint, model, key_encrypted
        row.proxy_mode, row.proxy_url_encrypted = proxy_mode, proxy_url_encrypted
        row.capabilities_json = capabilities
        row.enabled = bool(data.get("enabled", row.enabled if not creating else True))
        row.priority = clamp(data.get("priority", row.priority if not creating else 100), 1, 1000, 100)
        row.weight = clamp(data.get("weight", row.weight if not creating else 1), 1, 10, 1)
        row.max_concurrency = clamp(data.get("max_concurrency", row.max_concurrency if not creating else 1), 1, 8, 1)
        limits = data.get("limits") if isinstance(data.get("limits"), dict) else None
        if limits is None and creating and "limits" not in data:
            limits = quota.preset_for(provider, endpoint, model)  # a known free tier: start from its published allowance
            limits = {("tz" if k == "quota_tz" else k[:-6]): v for k, v in (limits or {}).items()} or None
        if limits is not None:
            for field, attribute in (("rpm", "rpm_limit"), ("tpm", "tpm_limit"), ("rpd", "rpd_limit")):
                value = limits.get(field)
                setattr(row, attribute, None if value in (None, "") else clamp(value, 0, 10**9, 0))
            zone = str(limits.get("tz") or "UTC")
            row.quota_tz = zone if quota.valid_timezone(zone) else "UTC"
        row.cooldown_until = None if creating or old_destination != (provider, endpoint) else row.cooldown_until
        if not creating and (old_destination != (provider, endpoint)):
            row.consecutive_failures, row.last_test_ok, row.last_test_at = 0, None, None
        config.revision += 1
        config.updated_by_id = current_user.id
        service.cancel_active(current_user.tenant_id)
        db.session.flush()
        audit("ai service " + ("added" if creating else "changed"), row.id,
              f"provider={provider}; location={'external' if row.external else 'private'}; enabled={row.enabled}")
        return row

    def owned_service(service_id):
        return AIConnection.query.filter_by(id=service_id, tenant_id=current_user.tenant_id).first_or_404()

    def tenant_config(create=False):
        config = AIConfiguration.query.filter_by(tenant_id=current_user.tenant_id).with_for_update().first()
        if not config and create:
            config = AIConfiguration(tenant_id=current_user.tenant_id, revision=0, key_encrypted="")
            db.session.add(config)
            db.session.flush()
        return config

    @blueprint.route("/admin/ai", methods=["GET", "POST"])
    @roles("admin")
    @require_action("administer")
    def settings():
        service.actor(current_user)
        config = tenant_config()
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
                flash("AI is off. Queued work is cancelled; answers still being written are discarded.", "success")
                return redirect(url_for("ai.settings"))
            if action != "save":
                abort(400)
            config = tenant_config(create=True)
            try:
                if request.form.get("provider"):
                    # Single-service form (older clients and the API): stored as the "Primary" service.
                    primary = AIConnection.query.filter_by(tenant_id=current_user.tenant_id, name="Primary").first()
                    form = request.form.to_dict()
                    form["name"] = "Primary"
                    save_service(config, form, primary)
                config.enabled = request.form.get("enabled") == "on"
                config.incident_enabled = request.form.get("incident_enabled") == "on"
                config.chat_enabled = request.form.get("chat_enabled") == "on"
                config.actions_enabled = request.form.get("actions_enabled") == "on"
                config.show_reasoning = request.form.get("show_reasoning") == "on"
                config.external_consent = request.form.get("external_consent") == "on"
                mode = request.form.get("routing_mode", config.routing_mode or "smart")
                scope = request.form.get("external_scope", config.external_scope or "not_sensitive")
                if mode not in routing.ROUTING_MODES or scope not in routing.EXTERNAL_SCOPES:
                    raise ProviderError("Choose one of the listed options.")
                config.routing_mode, config.external_scope = mode, scope
                if "routing_mode" in request.form:  # the full settings form; older clients leave these untouched
                    config.memory_enabled = request.form.get("memory_enabled") == "on"
                    for flag in ("detect_personal", "detect_credentials", "detect_financial"):
                        setattr(config, flag, request.form.get(flag) == "on")
                if "sensitive_terms" in request.form:
                    config.sensitive_terms = "\n".join(routing.custom_terms(SimpleNamespace(
                        sensitive_terms=request.form["sensitive_terms"])))[:4000]
                for name, low, high, default in (("daily_limit", 1, 1000, 100), ("max_output_tokens", 128, 4096, 1500),
                                                 ("retention_days", 1, 30, 7)):
                    value = int(request.form.get(name, getattr(config, name) or default))
                    if not low <= value <= high:
                        raise ProviderError(f"{name.replace('_', ' ').capitalize()} must be between {low} and {high}.")
                    setattr(config, name, value)
                db.session.flush()
                if config.enabled:
                    if ipfs_enabled():
                        raise ProviderError("AI jobs require PostgreSQL storage; IPFS mode is not supported.")
                    service.ready(config)
                config.revision += 1
                config.updated_by_id = current_user.id
                service.cancel_active(current_user.tenant_id)
                audit("ai configured", "AI configuration",
                      f"enabled={config.enabled}; incidents={config.incident_enabled}; chat={config.chat_enabled}; "
                      f"actions={config.actions_enabled}; "
                      f"routing={config.routing_mode}; external={config.external_scope}; revision={config.revision}")
                db.session.commit()
                flash("Saved. Requests waiting or being answered were cancelled so the new settings apply cleanly.", "success")
            except (ProviderError, ValueError) as error:
                db.session.rollback()
                flash(str(error) if isinstance(error, ProviderError) else "Enter valid numbers for the limits.", "error")
            return redirect(url_for("ai.settings"))
        rows = service.connections_for(config) if config else []
        counts = routing.running_counts(current_user.tenant_id)
        per_service, today = routing.usage_today(current_user.tenant_id)
        calls = quota.recent_calls(current_user.tenant_id)
        return render_template("ai_settings.html", config=config, ipfs=ipfs_enabled(), modes=routing.ROUTING_MODES,
                               services=[service_payload(r, counts, per_service, calls) for r in rows],
                               today=today, daily_limit=config.daily_limit if config else 100)

    @blueprint.route("/admin/ai/services", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def service_save():
        service.actor(current_user)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return no_store({"error": "Expected a JSON object."}, 400)
        config = tenant_config(create=True)
        row = owned_service(str(data["id"])) if data.get("id") else None
        try:
            row = save_service(config, data, row)
            db.session.commit()
        except ProviderError as error:
            db.session.rollback()
            return no_store({"error": str(error)}, 400)
        return no_store({"service": service_payload(row, routing.running_counts(current_user.tenant_id), routing.usage_today(current_user.tenant_id)[0], quota.recent_calls(current_user.tenant_id))})

    @blueprint.route("/admin/ai/services/bulk", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def service_bulk():
        """Add several models from one provider account in one step (each is its own service with its own allowance)."""
        service.actor(current_user)
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("models"), list):
            return no_store({"error": "Expected a list of models."}, 400)
        config = tenant_config(create=True)
        models = [str(m)[:160] for m in data["models"]][:12]
        source = AIConnection.query.filter_by(id=str(data["from_service_id"]), tenant_id=current_user.tenant_id).first() \
            if data.get("from_service_id") else None
        typed = str(data.get("api_key", "")).strip()
        made = []
        try:
            for model in models:
                if AIConnection.query.filter_by(tenant_id=current_user.tenant_id, provider=str(data.get("provider")),
                                                endpoint=normalize_endpoint(str(data.get("endpoint", ""))) if data.get("provider") in {
                                                    "self_hosted", "openai_compatible"} else "", model=model).first():
                    continue  # already added
                body = {"name": model[:80], "provider": data.get("provider"), "endpoint": data.get("endpoint", ""), "model": model,
                        "api_key": typed or (decrypt_key(source) if source and source.key_encrypted else ""), "enabled": True,
                        "proxy_mode": getattr(source, "proxy_mode", "default") if source else "default",
                        "proxy_url": (settings_cipher().decrypt(source.proxy_url_encrypted.encode()).decode()
                                      if source and source.proxy_url_encrypted else "")}
                made.append(save_service(config, body))
            db.session.commit()
        except ProviderError as error:
            db.session.rollback()
            return no_store({"error": str(error)}, 400)
        counts = routing.running_counts(current_user.tenant_id)
        per, _ = routing.usage_today(current_user.tenant_id)
        calls = quota.recent_calls(current_user.tenant_id)
        return no_store({"services": [service_payload(r, counts, per, calls) for r in made]})

    @blueprint.route("/admin/ai/services/<service_id>/delete", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def service_delete(service_id):
        service.actor(current_user)
        config = tenant_config(create=True)
        row = owned_service(service_id)
        AIRun.query.filter_by(connection_id=row.id).update({"connection_id": None}, synchronize_session=False)
        db.session.delete(row)
        config.revision += 1
        service.cancel_active(current_user.tenant_id)
        audit("ai service removed", service_id, "Deleted by an administrator")
        db.session.commit()
        return no_store({"deleted": True})

    @blueprint.route("/admin/ai/services/<service_id>/test", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def service_test(service_id):
        from app import route_rate_limit
        service.actor(current_user)
        row = owned_service(service_id)
        config = tenant_config(create=True)
        if not route_rate_limit("ai_probe", f"tenant:{current_user.tenant_id}", 10):
            db.session.commit()
            return no_store({"error": "Too many tests. Wait a minute."}, 429)
        snapshot = service._snapshot(config, row)
        snapshot.external_consent = True
        audit("ai connection test", row.id, "Synthetic prompt only; no operational records")
        db.session.commit()
        started = time.monotonic()
        try:
            generate(snapshot, [], probe=True)
            ok, message = True, "Connected. The service answered a test question."
        except ProviderError as error:
            ok, message = False, str(error)
        row = owned_service(service_id)
        row.last_test_ok, row.last_test_at = ok, now()
        if ok:
            routing.record_success(row)
        db.session.commit()
        return no_store({"ok": ok, "message": message, "ms": int((time.monotonic() - started) * 1000),
                         "service": service_payload(row, routing.running_counts(current_user.tenant_id), routing.usage_today(current_user.tenant_id)[0],
                                                    quota.recent_calls(current_user.tenant_id))})

    @blueprint.route("/admin/ai/preview", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def route_preview():
        """Show, with the real rules, where a request would go. Nothing is sent to any AI service."""
        service.actor(current_user)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return no_store({"error": "Expected a JSON object."}, 400)
        config = tenant_config(create=True)
        pick = lambda name, ok, fallback: data.get(name) if data.get(name) in ok else fallback  # noqa: E731
        trial = SimpleNamespace(
            external_consent=data.get("external_consent") is True if "external_consent" in data else config.external_consent,
            routing_mode=pick("routing_mode", routing.ROUTING_MODES, config.routing_mode),
            external_scope=pick("external_scope", routing.EXTERNAL_SCOPES, config.external_scope),
            detect_personal=data.get("detect_personal", config.detect_personal) is True,
            detect_credentials=data.get("detect_credentials", config.detect_credentials) is True,
            detect_financial=data.get("detect_financial", config.detect_financial) is True,
            sensitive_terms=str(data.get("sensitive_terms", config.sensitive_terms))[:4000])
        text = str(data.get("text", ""))[:4000]
        kinds = {k for k in data.get("kinds", ["ticket"]) if k in {"ticket", "knowledge", "ci"}} if isinstance(
            data.get("kinds", ["ticket"]), list) else {"ticket"}
        reasons = routing.scan(text, trial)
        chosen = routing.plan(trial, service.connections_for(config), reasons, kinds, {}, random.Random(0))
        return no_store({
            "sensitive": chosen.sensitive, "reasons": [routing.REASON_TEXT[r] for r in chosen.reasons],
            "blocked": routing.BLOCKED_TEXT.get(chosen.blocked, "") if chosen.blocked else "",
            "eligible": [{"name": c.name, "external": c.external} for c in chosen.candidates],
            "note": chosen.note})

    @blueprint.route("/admin/ai/models", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def detect_models():
        """List the models a server offers, so an administrator only has to give an address and a key.
        The entered key is used for this one request and never stored or echoed."""
        from app import route_rate_limit
        service.actor(current_user)
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return no_store({"error": "Expected a JSON object."}, 400)
        provider = str(data.get("provider", "self_hosted"))
        if provider not in PROVIDERS:
            return no_store({"error": "Choose a supported provider."}, 400)
        if not route_rate_limit("ai_probe", f"tenant:{current_user.tenant_id}", 10):
            db.session.commit()
            return no_store({"error": "Too many attempts. Wait a minute."}, 429)
        saved = None
        if data.get("service_id"):
            saved = AIConnection.query.filter_by(id=str(data["service_id"]), tenant_id=current_user.tenant_id).first()
        elif AIConnection.query.filter_by(tenant_id=current_user.tenant_id).count() <= 1:
            saved = AIConnection.query.filter_by(tenant_id=current_user.tenant_id).first() or AIConfiguration.query.filter_by(
                tenant_id=current_user.tenant_id).first()
        endpoint = str(data.get("endpoint", ""))[:500]
        typed_key = str(data.get("api_key", "")).strip()
        if len(typed_key) > 4096 or any(char in typed_key for char in "\r\n"):
            return no_store({"error": "Invalid API key."}, 400)
        proxy_mode = str(data.get("proxy_mode", getattr(saved, "proxy_mode", "default") if saved else "default"))
        if proxy_mode not in {"default", "none", "custom"}:
            return no_store({"error": "Choose a supported proxy option."}, 400)
        typed_proxy = str(data.get("proxy_url", "")).strip()
        saved_proxy = ""
        if proxy_mode == "custom" and not typed_proxy and saved and getattr(saved, "proxy_url_encrypted", ""):
            try:
                saved_proxy = settings_cipher().decrypt(saved.proxy_url_encrypted.encode()).decode()
            except Exception:
                return no_store({"error": "AI proxy credential could not be decrypted."}, 400)
        from app import setting_value
        candidate = SimpleNamespace(provider=provider, endpoint=endpoint, model=str(data.get("model", ""))[:160], key_encrypted="",
                                    external_consent=True, max_output_tokens=64, proxy_mode=proxy_mode,
                                    proxy_url=typed_proxy or saved_proxy,
                                    default_proxy_url=setting_value("OUTBOUND_PROXY_URL", ""))
        try:
            candidate.endpoint = normalize_endpoint(endpoint) if provider in {"self_hosted", "openai_compatible"} else ""
            if typed_key:
                key = typed_key
                candidate.key_encrypted = "typed"  # presence marker only; the key itself is passed directly
            elif not data.get("clear_key") and saved and saved.key_encrypted and (saved.provider, saved.endpoint) == (provider, candidate.endpoint):
                key, candidate.key_encrypted = decrypt_key(saved), saved.key_encrypted
            else:
                key = ""
            audit("ai model discovery", "AI configuration", f"provider={provider}")
            db.session.commit()
            context, profiles = {}, {}
            models = list_models(candidate, key, context, profiles)
            token = discovery_tokens.issue(candidate, key, profiles, current_user.tenant_id, current_user.id)
            quotas = {m: p for m in models if (p := quota.preset_for(provider, candidate.endpoint, m))}
            return no_store({"models": models, "context": context, "profiles": profiles, "discovery_token": token,
                             "quotas": quotas})
        except ProviderError as error:
            return no_store({"error": str(error)}, 400)

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
                service.ready(config)
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
                        provider="auto", model="auto")
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
        source_links(sources)
        return render_template("ai_result.html", run=run, ticket=ticket, sources=sources, config=config)

    def owned_action(action_id, *, lock=False):
        query = AIAction.query.filter_by(id=action_id, tenant_id=current_user.tenant_id,
                                         proposed_by_id=current_user.id)
        return (query.with_for_update() if lock else query).first_or_404()

    @blueprint.post("/ai/chat/runs/<run_id>/actions/prepare")
    @login_required
    def prepare_chat_action(run_id):
        """Freeze a deterministic staff chat command, or a staff-requested generated draft, as an expiring proposal.
        Ticket state/priority/assignment stays administrator-only; comments, notes and knowledge drafts are open
        to any staff role, matching who may already post a comment or write a knowledge article by hand."""
        from app import visible_ticket_query
        from serviceops_core.ai import actions

        scope, config = chat_scope()
        if not scope.is_staff:
            abort(403, description="Staff access is required for AI actions.")
        if not config.actions_enabled:
            abort(403, description="AI ticket actions are disabled by your administrator.")
        run = AIRun.query.filter_by(id=run_id, tenant_id=scope.tenant_id, user_id=scope.user_id,
                                    actor_role=scope.role, kind="chat", status="completed").with_for_update().first_or_404()
        if not access.sources_still_accessible(scope, json.loads(run.sources_json or "[]")):
            abort(403, description="You no longer have access to all evidence used by this answer.")
        candidate = json.loads(run.route_json or "{}").get("action")
        supported = {"add_comment", "update_ticket", "kb_article", *actions.DRAFT_COMMENT_PREFIX}
        if not isinstance(candidate, dict) or candidate.get("type") not in supported:
            abort(409, description="This answer does not contain a supported action proposal.")
        if candidate["type"] == "update_ticket" and scope.role not in ("admin", "superadmin"):
            abort(403, description="Administrator access is required to change ticket state, priority or assignment.")
        ticket = visible_ticket_query(scope.identity).filter_by(
            number=candidate.get("ticket"), deleted_at=None).first_or_404()
        existing = AIAction.query.filter_by(run_id=run.id, action_type=candidate["type"]).first()
        if existing:
            return no_store({"url": url_for("ai.action_review", action_id=existing.id)})
        action = AIAction(
            tenant_id=scope.tenant_id, run_id=run.id, ticket_id=ticket.id,
            proposed_by_id=scope.user_id, actor_role=scope.role, action_type=candidate["type"],
            payload_json=json.dumps(candidate.get("payload", {})), target_updated_at=ticket.updated_at,
            expires_at=now() + timedelta(minutes=15),
        )
        db.session.add(action)
        db.session.flush()
        audit("ai action proposed", action.id, f"type={action.action_type}; ticket={ticket.number}")
        db.session.commit()
        return no_store({"url": url_for("ai.action_review", action_id=action.id)}, 201)

    @blueprint.post("/ai/runs/<run_id>/actions/comment")
    @login_required
    def propose_comment(run_id):
        """Freeze the completed answer as an exact, expiring ticket-comment proposal."""
        identity = service.actor(current_user)
        config = service.enabled_config(identity.tenant_id)
        if not config.actions_enabled:
            abort(403, description="AI ticket actions are disabled by your administrator.")
        run = AIRun.query.filter_by(id=run_id, tenant_id=identity.tenant_id,
                                    user_id=identity.id, kind="investigation").with_for_update().first_or_404()
        if run.actor_role != identity.role:
            abort(403, description="Switch to the role used to request this investigation.")
        if run.status != "completed" or not run.result_text.strip():
            abort(409, description="Only a completed investigation can become a ticket action.")
        if not service.sources_accessible(identity, json.loads(run.sources_json or "[]")):
            abort(403, description="You no longer have access to all evidence used by this investigation.")
        ticket = service.visible_incident(identity, run.ticket_id)
        existing = AIAction.query.filter_by(run_id=run.id, action_type="add_comment").first()
        if existing:
            return redirect(url_for("ai.action_review", action_id=existing.id))
        action = AIAction(
            tenant_id=identity.tenant_id, run_id=run.id, ticket_id=ticket.id,
            proposed_by_id=identity.id, actor_role=identity.role, action_type="add_comment",
            payload_json=json.dumps({"body": run.result_text[:10000]}),
            target_updated_at=ticket.updated_at, expires_at=now() + timedelta(minutes=15),
        )
        db.session.add(action)
        db.session.flush()
        audit("ai action proposed", action.id, f"type=add_comment; ticket={ticket.number}")
        db.session.commit()
        return redirect(url_for("ai.action_review", action_id=action.id))

    @blueprint.route("/ai/actions/<action_id>", methods=["GET", "POST"])
    @login_required
    def action_review(action_id):
        from app import visible_ticket_query
        from serviceops_core.ai import actions

        action = owned_action(action_id, lock=request.method == "POST")
        run = AIRun.query.filter_by(id=action.run_id, tenant_id=action.tenant_id).first_or_404()
        if run.kind == "chat":
            identity = access.build_scope(current_user)
            config = service.enabled_config(identity.tenant_id, feature="chat")
            sources_ok = access.sources_still_accessible(identity, json.loads(run.sources_json or "[]"))
            back_url = url_for("ai.chat_page")
        else:
            identity = service.actor(current_user)
            config = service.enabled_config(identity.tenant_id)
            sources_ok = service.sources_accessible(identity, json.loads(run.sources_json or "[]"))
            back_url = url_for("ai.result", run_id=run.id)
        actor_id = getattr(identity, "id", getattr(identity, "user_id", None))
        if action.actor_role != identity.role:
            abort(403, description="Switch to the role used to prepare this action.")
        ticket = visible_ticket_query(identity.identity if hasattr(identity, "identity") else identity).filter_by(
            id=action.ticket_id, deleted_at=None).first_or_404()
        payload = json.loads(action.payload_json)
        if request.method == "GET":
            return render_template("ai_action_review.html", action=action, ticket=ticket, payload=payload,
                                   fields=actions.describe_payload(action.action_type, payload),
                                   action_label=actions.action_label(action.action_type), back_url=back_url,
                                   expired=action.expires_at.replace(tzinfo=now().tzinfo) <= now())
        decision = request.form.get("decision")
        if decision == "reject" and action.status == "pending":
            action.status, action.approved_by_id, action.decided_at = "rejected", actor_id, now()
            audit("ai action rejected", action.id, f"type={action.action_type}; ticket={ticket.number}")
            db.session.commit()
            return redirect(url_for("ai.action_review", action_id=action.id))
        if decision != "approve":
            abort(400)
        if action.status == "executed":
            return redirect(url_for("ai.action_review", action_id=action.id))
        if action.status != "pending":
            abort(409, description="This action is no longer awaiting approval.")
        if not config.actions_enabled:
            abort(403, description="AI ticket actions are disabled by your administrator.")
        if action.expires_at.replace(tzinfo=now().tzinfo) <= now():
            action.status, action.decided_at = "expired", now()
            db.session.commit()
            abort(410, description="This proposal expired. Prepare it again from a current investigation.")
        if not sources_ok:
            abort(403, description="You no longer have access to all evidence used by this investigation.")
        locked_ticket = Ticket.query.filter_by(id=ticket.id, tenant_id=identity.tenant_id).with_for_update().one()
        expected = action.target_updated_at.replace(tzinfo=now().tzinfo)
        actual = locked_ticket.updated_at.replace(tzinfo=now().tzinfo)
        if actual != expected:
            action.status, action.decided_at = "stale", now()
            audit("ai action stale", action.id, f"type={action.action_type}; ticket={ticket.number}")
            db.session.commit()
            abort(409, description="The ticket changed after this proposal was prepared. Run a new investigation first.")
        actions.execute(action, locked_ticket, current_user)
        action.status, action.approved_by_id = "executed", actor_id
        action.decided_at = action.executed_at = now()
        audit("ai action executed", action.id,
              f"type={action.action_type}; ticket={ticket.number}")
        db.session.commit()
        return redirect(url_for("ai.action_review", action_id=action.id))

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
            kind, record_id = source["kind"], source["record_id"]
            source["url"] = {
                "ticket": lambda: url_for("ticket_detail", ticket_id=record_id),
                "knowledge": lambda: url_for("knowledge_detail", article_id=record_id),
                "ci": lambda: url_for("ci_edit", ci_id=record_id),
                "enterprise": lambda: url_for("enterprise_detail", record_id=record_id),
                "request": lambda: url_for("request_detail", request_id=record_id),
                "client_ticket": lambda: url_for("client_ticket_detail", ticket_id=record_id),
                "asset": lambda: url_for("assets", q=source.get("number", "")),
            }[kind]()
        return sources

    def with_draft_link(route, run_id=None):
        """Turn a validated ticket draft into a link that opens the normal ticket form pre-filled."""
        pages = []
        for page in (route or {}).get("pages", []):
            try:
                pages.append({"label": page["label"], "url": url_for(page["endpoint"], **page.get("params", {}))})
            except Exception:  # noqa: BLE001 - a page that was renamed since must never break an answer
                continue
        if route and "pages" in route:
            route = {**route, "pages": pages}
        draft = (route or {}).get("draft")
        if draft:
            route = {**route, "draft": {**draft, "url": url_for(
                "ticket_new", kind=draft["kind"], ai="1", title=draft["title"], description=draft["description"],
                impact=draft["impact"], urgency=draft["urgency"], category=draft["category"])}}
        proposed_action = (route or {}).get("action")
        if proposed_action and run_id:
            public_action = {key: value for key, value in proposed_action.items() if key != "payload"}
            route = {**route, "action": {**public_action, "prepare_url": url_for(
                "ai.prepare_chat_action", run_id=run_id)}}
        return route

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
        if run.status == "failed" and run.error_code == "quota":
            problem_override = json.loads(run.route_json or "{}").get("reason", "")
        else:
            problem_override = ""
        problem = {"failed": problem_override or routing.BLOCKED_TEXT.get(
                       run.error_code, routing.RUN_ERROR_TEXT.get(
                           run.error_code, "The assistant could not complete this request.")),
                   "cancelled": "Stopped. No answer was kept."}.get(run.status, "")
        return no_store({**body, "changed": True, "text": run.result_text if finished else run.partial_text,
                         "reasoning": "",
                         "steps": json.loads(run.steps_json or "[]"), "sources": sources, "error": problem,
                         "route": with_draft_link(json.loads(run.route_json or "{}"), run.id) if finished else {},
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

    MAX_QUESTION = 2000
    MAX_MESSAGES = 100

    def chat_scope():
        """Who is asking, decided only from the signed-in session; request data never widens it."""
        try:
            scope = access.build_scope(current_user)
        except access.ScopeError:
            abort(403)
        return scope, service.enabled_config(scope.tenant_id, feature="chat")

    def owned_conversation(conversation_id, scope, lock=False):
        query = AIConversation.query.filter_by(id=conversation_id, tenant_id=scope.tenant_id, user_id=scope.user_id)
        conversation = (query.with_for_update() if lock else query).first_or_404()
        if conversation.actor_role != scope.role:
            abort(403, description="Switch to the role you used for this conversation.")
        return conversation

    def message_payload(message, scope, config, run):
        body = {"id": message.id, "role": message.role, "status": message.status, "content": message.content,
                "error": routing.BLOCKED_TEXT.get(run.error_code, "") if run and message.status == "failed" else "",
                "reasoning": "", "sources": [], "steps": [], "run_id": run.id if run else message.run_id,
                "created_at": message.created_at.isoformat()}
        if message.role != "assistant" or message.status != "completed":
            return body
        sources = json.loads(message.sources_json or "[]")
        if not access.sources_still_accessible(scope, sources):
            body.update(content=access.WITHHELD_NOTICE, withheld=True)
            return body
        body.update(route=with_draft_link(json.loads(message.route_json or "{}"), run.id if run else message.run_id), sources=source_links(sources),
                    steps=json.loads(message.steps_json or "[]"),
                    reasoning="")
        return body

    @blueprint.route("/ai/chat")
    @login_required
    def chat_page():
        scope, config = chat_scope()
        return render_template("ai_chat.html", scope=scope, config=config)

    @blueprint.route("/ai/chat/conversations")
    @login_required
    def chat_conversations():
        scope, config = chat_scope()
        rows = AIConversation.query.filter_by(tenant_id=scope.tenant_id, user_id=scope.user_id, actor_role=scope.role).order_by(
            AIConversation.updated_at.desc()).limit(50).all()
        return no_store({"scope": scope.summary(), "memory_enabled": bool(config.memory_enabled),
                         "show_reasoning": bool(config.show_reasoning), "conversations": [
            {"id": row.id, "title": row.title, "updated_at": row.updated_at.isoformat()} for row in rows]})

    @blueprint.route("/ai/chat/conversations/<conversation_id>")
    @login_required
    def chat_conversation(conversation_id):
        scope, config = chat_scope()
        conversation = owned_conversation(conversation_id, scope)
        runs = {run.message_id: run for run in AIRun.query.filter_by(conversation_id=conversation.id).all()}
        messages = AIMessage.query.filter_by(conversation_id=conversation.id).order_by(AIMessage.created_at).all()
        return no_store({"id": conversation.id, "title": conversation.title, "scope": scope.summary(),
                         "messages": [message_payload(m, scope, config, runs.get(m.id)) for m in messages]})

    @blueprint.route("/ai/chat/conversations/<conversation_id>/delete", methods=["POST"])
    @login_required
    def chat_delete(conversation_id):
        # Deleting stays possible when chat is switched off: people can always remove their own history.
        conversation = AIConversation.query.filter_by(id=conversation_id, tenant_id=current_user.tenant_id,
                                                      user_id=current_user.id).first_or_404()
        service.delete_conversation(conversation)
        audit("ai chat deleted", conversation_id, "Deleted by its owner")
        db.session.commit()
        return no_store({"deleted": True})

    def note_payload(note):
        return {"id": note.id, "text": note.text, "kind": note.kind, "source": note.source, "created_at": note.created_at.isoformat()}

    @blueprint.route("/ai/chat/memories")
    @login_required
    def memory_list():
        scope, config = chat_scope()
        return no_store({"enabled": bool(config.memory_enabled), "limit": memory.MAX_NOTES,
                         "notes": [note_payload(n) for n in memory.notes_for(scope)] if config.memory_enabled else []})

    @blueprint.route("/ai/chat/memories", methods=["POST"])
    @login_required
    def memory_add():
        scope, config = chat_scope()
        if not config.memory_enabled:
            abort(403, description="Your administrator has turned assistant memory off.")
        data = request.get_json(silent=True) or {}
        note, message = memory.store(scope, str(data.get("text", "")), config, source="suggested")
        if not note:
            return no_store({"error": message}, 400)
        audit("ai memory saved", note.id, "one note")
        db.session.commit()
        return no_store({"note": note_payload(note), "message": message}, 201)

    @blueprint.route("/ai/chat/memories/<note_id>/delete", methods=["POST"])
    @login_required
    def memory_delete(note_id):
        # Always allowed to the owner, even if the feature has since been switched off.
        note = AIMemory.query.filter_by(id=note_id, tenant_id=current_user.tenant_id, user_id=current_user.id).first_or_404()
        db.session.delete(note)
        audit("ai memory deleted", note_id, "Deleted by its owner")
        db.session.commit()
        return no_store({"deleted": True})

    @blueprint.route("/ai/chat/memories/clear", methods=["POST"])
    @login_required
    def memory_clear():
        total = AIMemory.query.filter_by(tenant_id=current_user.tenant_id, user_id=current_user.id).delete(synchronize_session=False)
        audit("ai memory cleared", str(current_user.id), f"notes={total}")
        db.session.commit()
        return no_store({"cleared": total})

    @blueprint.route("/ai/chat/messages", methods=["POST"])
    @login_required
    def chat_send():
        from app import route_rate_limit
        scope, _ = chat_scope()
        data = request.get_json(silent=True) or {}
        text = data.get("text")
        if not isinstance(text, str) or not text.strip():
            abort(400, description="Type a question first.")
        text = text.strip()
        if len(text) > MAX_QUESTION:
            abort(400, description=f"Questions are limited to {MAX_QUESTION} characters.")
        try:
            request_key = str(uuid.UUID(str(data.get("request_key", ""))))
        except ValueError:
            abort(400, description="Reload the page and try again.")
        if not route_rate_limit("ai_chat", f"user:{scope.user_id}", 20):
            db.session.commit()
            abort(429, description="You are sending messages too quickly. Wait a moment.")
        # The configuration row lock serializes submissions and daily quota accounting.
        config = service.enabled_config(scope.tenant_id, lock=True, feature="chat")
        existing = AIRun.query.filter_by(tenant_id=scope.tenant_id, user_id=scope.user_id, request_key=request_key).first()
        if existing:
            return no_store({"run_id": existing.id, "conversation_id": existing.conversation_id, "message_id": existing.message_id})
        try:
            service.ready(config)
        except ProviderError as error:
            abort(409, description=str(error))
        start = now().replace(hour=0, minute=0, second=0, microsecond=0)
        if AIRun.query.filter(AIRun.tenant_id == scope.tenant_id, AIRun.created_at >= start).count() >= config.daily_limit:
            abort(429, description="Your organization has reached its daily AI request limit.")
        if AIRun.query.filter(AIRun.tenant_id == scope.tenant_id, AIRun.user_id == scope.user_id,
                              AIRun.status.in_(service.ACTIVE)).first():
            abort(409, description="Wait for the current answer to finish, or stop it.")
        conversation_id = data.get("conversation_id")
        if conversation_id:
            conversation = owned_conversation(str(conversation_id), scope, lock=True)
            if AIMessage.query.filter_by(conversation_id=conversation.id).count() >= MAX_MESSAGES:
                abort(409, description="This conversation is full. Start a new chat.")
        else:
            conversation = AIConversation(tenant_id=scope.tenant_id, user_id=scope.user_id, actor_role=scope.role,
                                          title=" ".join(text.split())[:60] or "New chat")
            db.session.add(conversation)
            db.session.flush()
        db.session.add(AIMessage(conversation_id=conversation.id, tenant_id=scope.tenant_id, user_id=scope.user_id,
                                 role="user", content=text, status="completed"))
        reply = AIMessage(conversation_id=conversation.id, tenant_id=scope.tenant_id, user_id=scope.user_id,
                          role="assistant", status="pending")
        db.session.add(reply)
        db.session.flush()
        run = AIRun(tenant_id=scope.tenant_id, user_id=scope.user_id, actor_role=scope.role, kind="chat",
                    config_revision=config.revision, request_key=request_key, provider="auto", model="auto",
                    prompt_version="chat-v1", conversation_id=conversation.id, message_id=reply.id, question=text,
                    usage_json="{}")
        db.session.add(run)
        db.session.flush()
        audit("ai chat requested", run.id, f"role={scope.role}; length={len(text)}")
        db.session.commit()
        return no_store({"run_id": run.id, "conversation_id": conversation.id, "message_id": reply.id}, 201)


    app.register_blueprint(blueprint)
    app.jinja_env.globals["ai_available"] = service.available
    app.jinja_env.globals["ai_chat_available"] = service.chat_available
