"""Configuration items can be found and linked by serial number."""
import os
import tempfile

import pytest

from app import CiClassPermission, ConfigurationItem, User, create_app, db


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        tenant = User.query.filter_by(username="admin").one().tenant_id
        db.session.add_all([
            ConfigurationItem(name="db-prod-07", ci_class="Server", serial_number="CZJ1234ABC", tenant_id=tenant),
            ConfigurationItem(name="CZJ1234ABC-notes", ci_class="Document", tenant_id=tenant),
            ConfigurationItem(name="sw-core-01", ci_class="Network Switch", serial_number="FOC_99%X", tenant_id=tenant),
            ConfigurationItem(name="sw-core-02", ci_class="Network Switch", serial_number="FOC199AX", tenant_id=tenant),
        ])
        db.session.commit()
    yield app
    os.unlink(path)


@pytest.fixture()
def client(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "Admin123!"})
    return client


def test_lookup_finds_a_ci_by_serial_and_lists_an_exact_match_first(client):
    results = client.get("/internal/lookup/cis?q=czj1234abc").get_json()
    assert [r["label"] for r in results] == ["db-prod-07", "CZJ1234ABC-notes"]
    assert results[0]["description"].endswith("S/N CZJ1234ABC")


def test_serial_search_treats_wildcard_characters_literally(client):
    assert [r["label"] for r in client.get("/internal/lookup/cis?q=FOC_99%25").get_json()] == ["sw-core-01"]


def test_browse_dialog_searches_and_shows_serial_numbers(client):
    payload = client.get("/internal/lookup/cis/browse?q=CZJ1234").get_json()
    row = next(r for r in payload["results"] if r["name"] == "db-prod-07")
    assert row["serial_number"] == "CZJ1234ABC"
    assert next(r for r in payload["results"] if r["name"] == "CZJ1234ABC-notes")["serial_number"] == "—"


def test_serial_search_respects_ci_class_read_policy(app, client):
    with app.app_context():
        tenant = User.query.filter_by(username="admin").one().tenant_id
        db.session.add(CiClassPermission(tenant_id=tenant, ci_class="Server", role="manager", can_read=True))
        db.session.commit()
    client.post("/logout")
    with app.app_context():
        from werkzeug.security import generate_password_hash
        db.session.add(User(username="serial.agent", name="Serial Agent", email="serial.agent@test.invalid",
                            role="agent", password_hash=generate_password_hash("Agent123!"), tenant_id=tenant))
        db.session.commit()
    client.post("/login", data={"username": "serial.agent", "password": "Agent123!"})
    assert [r["label"] for r in client.get("/internal/lookup/cis?q=CZJ1234ABC").get_json()] == ["CZJ1234ABC-notes"]
