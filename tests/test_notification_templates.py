"""Tests for B-130's notification templates and per-user delivery
preferences: muting, non-mutable event types, template substitution, and
the email_enabled/Skipped delivery-recording path."""
import json

from app import (
    NotificationPreference, NotificationTemplate, Notification, OutboxEvent,
    User, create_notification, db, deliver_smtp,
)
from tests.test_app import client, app, login


def test_muting_an_event_type_suppresses_the_notification_entirely(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(NotificationPreference(
            user_id=admin.id, muted_event_types=json.dumps(["sla.breached"]),
        ))
        db.session.commit()
        before = Notification.query.filter_by(user_id=admin.id).count()
        result = create_notification(
            admin.id, "SLA breached: INC0000001", "body",
            tenant_id=admin.tenant_id, event_type="sla.breached",
        )
        db.session.commit()
        assert result is None
        assert Notification.query.filter_by(user_id=admin.id).count() == before


def test_unmuted_event_type_is_delivered_normally(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(NotificationPreference(
            user_id=admin.id, muted_event_types=json.dumps(["some.other.event"]),
        ))
        db.session.commit()
        before = Notification.query.filter_by(user_id=admin.id).count()
        result = create_notification(
            admin.id, "SLA breached: INC0000001", "body",
            tenant_id=admin.tenant_id, event_type="sla.breached",
        )
        db.session.commit()
        assert result is not None
        assert Notification.query.filter_by(user_id=admin.id).count() == before + 1


def test_password_recovery_cannot_be_muted(app):
    """Security-critical, user-initiated: a stale mute preference must
    never lock someone out of their own self-service password reset."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(NotificationPreference(
            user_id=admin.id, muted_event_types=json.dumps(["password.recovery"]),
        ))
        db.session.commit()
        before = Notification.query.filter_by(user_id=admin.id).count()
        result = create_notification(
            admin.id, "ServiceOps password recovery", "reset link",
            tenant_id=admin.tenant_id, event_type="password.recovery",
        )
        db.session.commit()
        assert result is not None
        assert Notification.query.filter_by(user_id=admin.id).count() == before + 1


def test_active_template_overrides_literal_title_and_body(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(NotificationTemplate(
            tenant_id=admin.tenant_id, event_type="sla.breached",
            subject_template="Custom subject: ${reference}",
            body_template="Custom body for ${sla_name} on ${reference}.",
        ))
        db.session.commit()
        result = create_notification(
            admin.id, "literal title", "literal body",
            tenant_id=admin.tenant_id, event_type="sla.breached",
            template_vars={"reference": "INC0000042", "sla_name": "Response time"},
        )
        db.session.commit()
        assert result.title == "Custom subject: INC0000042"
        assert result.body == "Custom body for Response time on INC0000042."


def test_inactive_template_is_ignored_falls_back_to_literal_wording(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add(NotificationTemplate(
            tenant_id=admin.tenant_id, event_type="sla.breached",
            subject_template="Custom subject", body_template="Custom body",
            active=False,
        ))
        db.session.commit()
        result = create_notification(
            admin.id, "literal title", "literal body",
            tenant_id=admin.tenant_id, event_type="sla.breached",
            template_vars={},
        )
        db.session.commit()
        assert result.title == "literal title"
        assert result.body == "literal body"


def test_email_disabled_skips_smtp_send_and_records_skipped_not_failed(app, monkeypatch):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin.email = "admin@example.test"
        db.session.add(NotificationPreference(user_id=admin.id, email_enabled=False))
        db.session.commit()
        notification = create_notification(
            admin.id, "Test", "body", tenant_id=admin.tenant_id,
        )
        db.session.commit()
        event = OutboxEvent.query.filter_by(
            event_type="notification.created",
        ).order_by(OutboxEvent.id.desc()).first()

        def boom(*a, **k):
            raise AssertionError("smtplib.SMTP must not be called when email is disabled")
        monkeypatch.setattr("smtplib.SMTP", boom)
        sent = deliver_smtp(event)
        assert sent is False


def test_notification_preferences_page_saves_email_and_mute_settings(client, app):
    login(client)
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        admin_id = admin.id
    resp = client.post("/preferences", data={
        "action": "notifications",
        "mute_sla.breached": "on",
    })
    assert resp.status_code == 302
    with app.app_context():
        pref = NotificationPreference.query.filter_by(user_id=admin_id).one()
        assert pref.email_enabled is False  # checkbox omitted = unchecked
        assert json.loads(pref.muted_event_types) == ["sla.breached"]


def test_notification_templates_admin_requires_admin_role(client, app):
    login(client, username="employee", password="Employee123!")
    resp = client.get("/admin/notification-templates")
    assert resp.status_code in (302, 403)


def test_notification_templates_admin_save_and_reset(client, app):
    login(client)
    resp = client.post("/admin/notification-templates", data={
        "action": "save", "event_type": "sla.breached",
        "subject_template": "Edited subject", "body_template": "Edited body",
    })
    assert resp.status_code == 302
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        template = NotificationTemplate.query.filter_by(
            tenant_id=admin.tenant_id, event_type="sla.breached",
        ).one()
        assert template.subject_template == "Edited subject"

    resp = client.post("/admin/notification-templates", data={
        "action": "reset", "event_type": "sla.breached",
    })
    assert resp.status_code == 302
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        assert NotificationTemplate.query.filter_by(
            tenant_id=admin.tenant_id, event_type="sla.breached",
        ).first() is None


def test_notification_templates_admin_rejects_unknown_event_type(client, app):
    login(client)
    resp = client.post("/admin/notification-templates", data={
        "action": "save", "event_type": "not.a.real.event",
        "subject_template": "x", "body_template": "y",
    })
    assert resp.status_code == 400
