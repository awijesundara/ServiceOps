"""Public profiles: names and pictures link to /people/<id>, which shows only
the fields the person made public, to signed-in users of the same tenant."""
import json
import os
import re

from werkzeug.security import generate_password_hash

from app import Comment, Tenant, Ticket, User, UserPreference, db
from tests.test_app import app, client, group_id, login  # noqa: F401 - pytest fixtures and helpers


def person(app, username, **fields):
    with app.app_context():
        defaults = dict(name=username.replace(".", " ").title(), email=f"{username}@corp.example",
                        password_hash=generate_password_hash("Passw0rd!x"), role="agent")
        defaults.update(fields)
        user = User(username=username, **defaults)
        db.session.add(user)
        db.session.commit()
        return user.id


def as_user(client, username, password="Passw0rd!x"):
    client.post("/logout")
    login(client, username, password)


def test_profile_shows_public_defaults_and_hides_private_ones(client, app):
    uid = person(app, "pat.lee", title="Network engineer", mobile_phone="+81 90 0000 1111",
                 business_phone="+81 3 0000 2222", employee_id="E-1001", timezone="Asia/Tokyo")
    login(client)
    page = client.get(f"/people/{uid}").get_data(as_text=True)
    assert "Pat Lee" in page and "Network engineer" in page and "pat.lee@corp.example" in page
    assert "+81 3 0000 2222" in page and "Asia/Tokyo" in page
    assert "+81 90 0000 1111" not in page and "E-1001" not in page  # private by default
    assert "What others can see" not in page  # only the owner gets the switches


def test_owner_controls_each_field_and_others_see_only_public_ones(client, app):
    uid = person(app, "sam.ito", title="DBA", mobile_phone="+81 80 1234 5678", location="Tokyo")
    as_user(client, "sam.ito")
    own = client.get(f"/people/{uid}").get_data(as_text=True)
    assert "What others can see" in own and 'name="public_email"' in own
    # Publish the mobile number; hide email and location.
    response = client.post("/profile/visibility", data={"public_title": "on", "public_mobile_phone": "on"})
    assert response.status_code == 302 and response.location.endswith(f"/people/{uid}")
    with app.app_context():
        stored = json.loads(UserPreference.query.filter_by(user_id=uid).one().profile_visibility_json)
        assert stored["mobile_phone"] is True and stored["email"] is False and stored["location"] is False
    as_user(client, "employee", "Employee123!")
    page = client.get(f"/people/{uid}").get_data(as_text=True)
    assert "+81 80 1234 5678" in page and "DBA" in page
    assert "sam.ito@corp.example" not in page and "Tokyo" not in page


def test_profiles_are_private_to_the_tenant_and_require_sign_in(client, app):
    uid = person(app, "kim.ra")
    assert client.get(f"/people/{uid}").status_code == 302  # to the sign-in page
    with app.app_context():
        other = Tenant(slug="profile-isolation", name="Other organisation")
        db.session.add(other)
        db.session.flush()
        outsider = User(username="outsider", name="Outsider", email="outsider@other.example",
                        password_hash=generate_password_hash("x" * 20), role="agent", tenant_id=other.id)
        db.session.add(outsider)
        db.session.commit()
        outsider_id = outsider.id
    login(client)
    assert client.get(f"/people/{outsider_id}").status_code == 404
    assert client.get(f"/profile/avatar/{outsider_id}").status_code == 404


def test_private_photo_is_hidden_from_others_but_not_from_owner_or_admin(client, app):
    uid = person(app, "lee.photo", avatar_path="user-photo-test.png")
    folder = os.path.join(app.config["UPLOAD_FOLDER"], "avatars")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "user-photo-test.png"), "wb") as handle:
        handle.write(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
    as_user(client, "employee", "Employee123!")
    assert client.get(f"/profile/avatar/{uid}").status_code == 200  # public by default
    as_user(client, "lee.photo")
    client.post("/profile/visibility", data={"public_title": "on"})  # photo now private
    assert client.get(f"/profile/avatar/{uid}").status_code == 200  # owner
    as_user(client, "employee", "Employee123!")
    assert client.get(f"/profile/avatar/{uid}").status_code == 404
    page = client.get(f"/people/{uid}").get_data(as_text=True)
    assert f"/profile/avatar/{uid}" not in page and "people-profile-initial" in page
    as_user(client, "admin", "Admin123!")
    assert client.get(f"/profile/avatar/{uid}").status_code == 200  # moderation


def test_names_pictures_and_mentions_on_a_ticket_link_to_profiles(client, app):
    login(client, "employee", "Employee123!")
    client.post("/tickets/new/incident", data={
        "title": "Profile links", "description": "x", "impact": "Low", "urgency": "Low", "group_id": group_id(app),
    })
    with app.app_context():
        ticket = Ticket.query.filter_by(title="Profile links").one()
        employee = User.query.filter_by(username="employee").one()
        admin = User.query.filter_by(username="admin").one()
        db.session.add(Comment(ticket_id=ticket.id, user_id=admin.id, body="Thanks @employee, looking now."))
        db.session.commit()
        ticket_id, employee_id, admin_id = ticket.id, employee.id, admin.id
    as_user(client, "admin", "Admin123!")
    page = client.get(f"/ticket/{ticket_id}").get_data(as_text=True)
    assert re.search(rf'<a class="person-link" href="/people/{employee_id}">', page)  # requester
    assert re.search(rf'<a class="person-avatar-link" href="/people/{admin_id}"', page)  # comment author
    assert f'<a class="mention" href="/people/{employee_id}">@employee</a>' in page
    # The ticket list links the requester too, and the sidebar opens your own profile.
    assert f'href="/people/{employee_id}"' in client.get("/tickets/incident").get_data(as_text=True)
    assert f'class="profile-identity" href="/people/{admin_id}"' in page


def test_unknown_mentions_and_missing_people_stay_plain_text(client, app):
    login(client)
    with app.app_context():
        from app import create_app  # noqa: F401 - app context for rendering helpers
        from flask import render_template_string
        with app.test_request_context():
            from flask_login import login_user
            login_user(User.query.filter_by(username="admin").one())
            assert 'class="mention"' in str(render_template_string("{{ mentions_html('hi @nobody') }}"))
            assert "<a" not in str(render_template_string("{{ mentions_html('hi @nobody') }}"))
            assert str(render_template_string("{{ user_link(none, 'Unassigned') }}")) == "Unassigned"
            assert str(render_template_string("{{ user_link(none, '<b>') }}")) == "&lt;b&gt;"
