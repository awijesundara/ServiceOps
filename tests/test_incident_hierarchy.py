"""Parent and child incidents: one parent, no loops, visible on both sides."""
from html.parser import HTMLParser

from app import RecordLink, Ticket, User, db
from serviceops_core import incident_hierarchy
from tests.test_app import app, client, group_id, login  # noqa: F401


def _incident(client, app, title, **extra):
    response = client.post("/tickets/new/incident", data={
        "title": title, "description": "Hierarchy check.", "category": "Software", "priority": "P3",
        "group_id": group_id(app), **extra})
    with app.app_context():
        row = Ticket.query.filter_by(title=title).first()
        return response, (row.id if row else None), (row.number if row else None)


class RecordForm(HTMLParser):
    """The incident page's own record form, so updates post exactly what a browser would."""
    def __init__(self):
        super().__init__();self.inside=False;self.fields={};self.select=None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and a.get("id") == "incident-record-form":self.inside = True
        if not self.inside:return
        if tag == "input" and a.get("name") and "disabled" not in a and a.get("type") not in ("checkbox", "radio"):
            self.fields[a["name"]] = a.get("value", "")
        if tag == "textarea" and a.get("name"):self.select = ("textarea", a["name"]);self.fields[a["name"]] = ""
        if tag == "select" and a.get("name") and "disabled" not in a:self.select = ("select", a["name"])
        if tag == "option" and self.select and self.select[0] == "select" and ("selected" in a or self.select[1] not in self.fields):
            # An option without a value attribute submits its text.
            self.fields[self.select[1]] = a.get("value", "");self.option_text = "value" not in a
        else:
            self.option_text = False
    def handle_data(self, data):
        if self.select and self.select[0] == "textarea":self.fields[self.select[1]] += data
        elif getattr(self, "option_text", False) and self.select:self.fields[self.select[1]] += data.strip();self.option_text = False
    def handle_endtag(self, tag):
        if tag in ("select", "textarea"):self.select = None
        if tag == "form":self.inside = False


def _update(client, ticket_id, **changes):
    form = RecordForm();form.feed(client.get(f"/ticket/{ticket_id}").get_data(as_text=True))
    return client.post(f"/ticket/{ticket_id}", data={**form.fields, **changes})


def test_parent_field_links_both_ways_and_labels_the_child(client, app):
    login(client)
    _, parent_id, parent_number = _incident(client, app, "Email outage (parent)")
    _, child_id, child_number = _incident(client, app, "Cannot send mail")
    assert _update(client, child_id, parent_incident=parent_number).status_code == 302
    child_page = client.get(f"/ticket/{child_id}").get_data(as_text=True)
    assert f'value="{parent_number}"' in child_page and f"Open {parent_number}" in child_page
    parent_page = client.get(f"/ticket/{parent_id}").get_data(as_text=True)
    assert "Child incidents" in parent_page and child_number in parent_page and "1 child" in parent_page
    assert f"Child incident · {child_number}" in parent_page and f"Parent incident · {child_number}" not in parent_page
    # Clearing the field removes the parent.
    assert _update(client, child_id, parent_incident="").status_code == 302
    with app.app_context():
        assert incident_hierarchy.parent_of(db.session.get(Ticket, child_id)) is None


def test_one_parent_no_self_no_loops_incidents_only(client, app):
    login(client)
    _, a_id, a_number = _incident(client, app, "Incident A")
    _, b_id, b_number = _incident(client, app, "Incident B")
    _, c_id, c_number = _incident(client, app, "Incident C")
    link = lambda source, number: client.post(f"/record/ticket/{source}/relationships",
                                              data={"link_type": "parent_incident", "target_number": number})
    assert link(b_id, a_number).status_code == 302
    assert link(b_id, c_number).status_code == 302  # replaces A, never two parents
    with app.app_context():
        assert RecordLink.query.filter_by(source_id=b_id, link_type="parent_incident").count() == 1
        assert incident_hierarchy.parent_of(db.session.get(Ticket, b_id)).id == c_id
    assert link(c_id, b_number).status_code == 409   # C -> B -> C would loop
    assert link(b_id, b_number).status_code == 400   # self
    assert client.post("/tickets/new/change", data={
        "title": "A change", "description": "x", "category": "Software", "priority": "P3", "change_type": "Standard",
        "risk_score": "20", "impact": "Low", "group_id": group_id(app), "implementation_plan": "i", "test_plan": "t",
        "backout_plan": "b", "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00"}).status_code == 302
    with app.app_context():
        change_number = Ticket.query.filter_by(kind="change").one().number
    assert link(a_id, change_number).status_code == 400
    assert link(a_id, "INC9999999").status_code == 404


def test_parent_chosen_when_creating_and_a_bad_parent_creates_nothing(client, app):
    login(client)
    _, parent_id, parent_number = _incident(client, app, "Network outage")
    response, child_id, _ = _incident(client, app, "Site cannot reach intranet", parent_incident=parent_number)
    assert response.status_code == 302
    with app.app_context():
        assert incident_hierarchy.parent_of(db.session.get(Ticket, child_id)).id == parent_id
    response, missing_id, _ = _incident(client, app, "Typo parent", parent_incident="INC9999999")
    assert response.status_code == 400 and missing_id is None
    assert b"No incident matches INC9999999" in response.data


def test_links_can_be_removed_by_the_team_but_not_by_requesters(client, app):
    login(client)
    _, parent_id, parent_number = _incident(client, app, "Parent to unlink")
    _, child_id, _ = _incident(client, app, "Child to unlink", parent_incident=parent_number)
    with app.app_context():
        link_id = RecordLink.query.filter_by(source_id=child_id, link_type="parent_incident").one().id
    client.post("/logout")
    login(client, "employee", "Employee123!")
    assert client.post(f"/record-links/{link_id}/delete").status_code in (403, 404)
    client.post("/logout")
    login(client)
    assert client.post(f"/record-links/{link_id}/delete").status_code == 302
    with app.app_context():
        assert RecordLink.query.filter_by(id=link_id).count() == 0


def test_parent_lookup_can_be_limited_to_incidents(client, app):
    login(client)
    _incident(client, app, "Lookup incident zebra")
    assert client.post("/tickets/new/change", data={
        "title": "Lookup change zebra", "description": "x", "category": "Software", "priority": "P3",
        "change_type": "Standard", "risk_score": "20", "impact": "Low", "group_id": group_id(app),
        "implementation_plan": "i", "test_plan": "t", "backout_plan": "b",
        "planned_start": "2026-08-01T09:00", "planned_end": "2026-08-01T17:00"}).status_code == 302
    kinds = {row["description"].split(" ·")[0] for row in client.get("/internal/lookup/records?q=zebra&kind=incident").json}
    assert kinds == {"Incident"}
    assert "Change" in {row["description"].split(" ·")[0] for row in client.get("/internal/lookup/records?q=zebra").json}
