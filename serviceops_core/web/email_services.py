"""Administration > Email delivery: the saved ways of sending email.

An administrator can save several services (a SendGrid account, a Microsoft
365 app, an SMTP relay...), each with only its own provider's fields, and
choose which one sends (the default) and which one takes over when the
default fails (the fallback). Services are install-wide, like the email
platform settings they replace, so every change needs the install settings
authority.
"""
import re

from flask import abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user

import app as core
from app import audit, require_action, require_install_settings_authority, roles
from serviceops_core.localization import tr
from serviceops_core.mail import (
    PROVIDERS, MailError, describe_service, legacy_service_config, provider_fields, send_with_service,
    test_message, validate_service,
)
from serviceops_models import MailService, PlatformSetting, db, now

_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _service_or_404(service_id):
    service = db.session.get(MailService, service_id)
    if service is None:
        abort(404)
    return service


def _set_enabled(value):
    row = db.session.get(PlatformSetting, "SMTP_ENABLED") or PlatformSetting(key="SMTP_ENABLED")
    db.session.add(row)
    row.value, row.encrypted, row.updated_by_id = "true" if value else "false", False, current_user.id


def _mark_services_active():
    """From now on only saved services send; the old settings are ignored."""
    row = db.session.get(PlatformSetting, "MAIL_SERVICES_ACTIVE") or PlatformSetting(key="MAIL_SERVICES_ACTIVE")
    db.session.add(row)
    row.value, row.encrypted, row.updated_by_id = "true", False, current_user.id


def _import_legacy():
    """An installation configured with the old email settings gets them as
    its first saved service, set as the default, so nothing stops sending."""
    if core.setting_bool("MAIL_SERVICES_ACTIVE") or MailService.query.first() is not None:
        return
    found = legacy_service_config()
    if not found:
        return
    _mark_services_active()
    provider, config = found
    service = MailService(name=PROVIDERS[provider]["label"], provider=provider, is_default=True,
                          created_by_id=current_user.id)
    service.config = config
    db.session.add(service)
    audit("configure", "Email service imported", f"{service.name}; from the email delivery settings")
    db.session.commit()


def _secret_keys(provider):
    return {field["key"] for field in provider_fields(provider) if field["type"] in ("secret", "secret_textarea")}


def register(app):
    @app.get("/admin/email")
    @roles("admin")
    @require_action("administer")
    def email_services():
        _import_legacy()
        services = MailService.query.order_by(MailService.is_default.desc(), MailService.is_fallback.desc(),
                                              MailService.name).all()
        rows = [dict(service=service, provider=PROVIDERS.get(service.provider, {}),
                     summary=describe_service(service.provider, service.config)) for service in services]
        return render_template(
            "email_services.html", rows=rows, providers=PROVIDERS, enabled=core.setting_bool("SMTP_ENABLED"),
            test_result=session.pop("email_service_test", None),
        )

    @app.post("/admin/email/enabled")
    @roles("admin")
    @require_action("administer")
    def email_services_enabled():
        require_install_settings_authority()
        enabled = request.form.get("enabled") == "true"
        _set_enabled(enabled)
        audit("configure", "Email notifications", "enabled" if enabled else "disabled")
        db.session.commit()
        flash(tr("Email notifications turned on.") if enabled else tr("Email notifications turned off."), "success")
        return redirect(url_for("email_services"))

    def _form(provider, service=None):
        if provider not in PROVIDERS:
            abort(404)
        spec = PROVIDERS[provider]
        config = service.config if service else {}
        method = config.get("method") or (next(iter(spec["methods"])) if spec.get("methods") else None)
        name = service.name if service else spec["label"]
        errors = []
        if request.method == "POST":
            require_install_settings_authority()
            name = (request.form.get("name") or "").strip()[:120]
            method = request.form.get("method") or method
            new_config, errors = validate_service(provider, method, request.form, existing=config)
            if not name:
                errors.insert(0, tr("Name is required."))
            if not errors:
                is_new = service is None
                if is_new:
                    has_default = MailService.query.filter_by(is_default=True).first() is not None
                    service = MailService(provider=provider, created_by_id=current_user.id, is_default=not has_default)
                service.name, service.config = name, new_config
                if is_new:
                    db.session.add(service)
                    _mark_services_active()
                service.last_test_ok = None if not is_new else service.last_test_ok
                audit("configure", "Email service saved", f"{name}; {spec['label']}; "
                      + ("created" if is_new else "updated"))
                db.session.commit()
                flash(tr("Email service saved. Send a test to check it."), "success")
                return redirect(url_for("email_services") + f"#service-{service.id}")
            for message in errors:
                flash(message, "error")
            # Re-show what was typed (never secrets); an unticked box is absent from the form.
            config = {**config, **{k: v for k, v in request.form.items() if k not in _secret_keys(provider)},
                      **{field["key"]: "true" if request.form.get(field["key"]) else "false"
                         for field in provider_fields(provider) if field["type"] == "bool"}}
        return render_template(
            "email_service_form.html", provider=provider, spec=spec, fields=provider_fields(provider),
            service=service, config=config, method=method, name=name, secrets_set={
                key for key in _secret_keys(provider) if (service.config if service else {}).get(key)},
        )

    @app.route("/admin/email/new/<provider>", methods=["GET", "POST"])
    @roles("admin")
    @require_action("administer")
    def email_service_new(provider):
        return _form(provider)

    @app.route("/admin/email/<int:service_id>", methods=["GET", "POST"])
    @roles("admin")
    @require_action("administer")
    def email_service_edit(service_id):
        service = _service_or_404(service_id)
        return _form(service.provider, service)

    @app.post("/admin/email/<int:service_id>/test")
    @roles("admin")
    @require_action("administer")
    def email_service_test(service_id):
        require_install_settings_authority()
        service = _service_or_404(service_id)
        allowed = core.route_rate_limit("email_service_test", f"user:{current_user.id}", 5)
        db.session.commit()
        if not allowed:
            abort(429, description=tr("Too many test emails. Try again in a minute."))
        recipient = (request.form.get("recipient") or current_user.email or "").strip()
        if not _EMAIL.fullmatch(recipient) or len(recipient) > 254:
            flash(tr("Enter a valid email address to send the test to."), "error")
            return redirect(url_for("email_services") + f"#service-{service.id}")
        instance = core.setting_value("INSTANCE_NAME", "ServiceOps") or "ServiceOps"
        service.last_tested_at = now()
        try:
            send_with_service(test_message(recipient, instance, service.name), service)
        except MailError as error:
            service.last_test_ok, service.last_test_message = False, f"{error.stage}: {error}"[:600]
            session["email_service_test"] = {"id": service.id, "ok": False, "stage": error.stage,
                                             "error": str(error)[:600]}
            audit("configure", "Email service test failed", f"{service.name}; {error.stage}; {str(error)[:300]}")
        else:
            service.last_test_ok, service.last_test_message = True, f"Accepted for {recipient}"
            session["email_service_test"] = {"id": service.id, "ok": True, "recipient": recipient}
            audit("configure", "Email service test sent", f"{service.name}; to={recipient}")
        db.session.commit()
        return redirect(url_for("email_services") + f"#service-{service.id}")

    @app.post("/admin/email/<int:service_id>/role")
    @roles("admin")
    @require_action("administer")
    def email_service_role(service_id):
        require_install_settings_authority()
        service = _service_or_404(service_id)
        role = request.form.get("role")
        if role not in ("default", "fallback", "none"):
            abort(400)
        if role == "default":
            MailService.query.filter(MailService.id != service.id).update({"is_default": False})
            service.is_default, service.is_fallback = True, False
        elif role == "fallback":
            if service.is_default:
                flash(tr("Choose another default first. The default cannot also be the fallback."), "error")
                return redirect(url_for("email_services"))
            MailService.query.filter(MailService.id != service.id).update({"is_fallback": False})
            service.is_fallback = True
        else:
            service.is_fallback = False
        audit("configure", "Email service role", f"{service.name}; {role}")
        db.session.commit()
        return redirect(url_for("email_services") + f"#service-{service.id}")

    @app.post("/admin/email/<int:service_id>/delete")
    @roles("admin")
    @require_action("administer")
    def email_service_delete(service_id):
        require_install_settings_authority()
        service = _service_or_404(service_id)
        if service.is_default and MailService.query.count() > 1:
            flash(tr("Make another service the default before removing this one."), "error")
            return redirect(url_for("email_services"))
        audit("configure", "Email service removed", service.name)
        db.session.delete(service)
        db.session.commit()
        flash(tr("Email service removed."), "success")
        return redirect(url_for("email_services"))
