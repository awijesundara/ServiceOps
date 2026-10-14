"""Stability fuzz: find routes that answer 500 for real or malformed input.

Run from the repository root with the test dependencies installed:

    python tools/stability_fuzz.py [get|forms|posts|api|all]
    FUZZ_DB_URL=postgresql+psycopg://user@/empty_db?host=/tmp python tools/stability_fuzz.py forms

FUZZ_DB_URL must name an empty, disposable database; the demo dataset is
loaded into it. Never point it at a real deployment.

Loads the demo dataset into a disposable SQLite database, signs in as the
administrator and:
  1. GETs every route with real ids and with garbage query parameters;
  2. parses every form on every page and submits it empty and with
     wrong-type values per field;
  3. sends malformed JSON to every API route (as a mobile session).
Each 500 is recorded with the traceback the app logged for it.
"""
import logging
import os
import re
import sys
import tempfile
from collections import defaultdict
from html.parser import HTMLParser

ROOT = os.getcwd()
sys.path.insert(0, ROOT)
sys.path.insert(0, ROOT + "/tools")
MODE = sys.argv[1] if len(sys.argv) > 1 else "all"

captured = []


class Capture(logging.Handler):
    def emit(self, record):
        if record.levelno >= logging.ERROR and record.exc_info:
            import traceback
            captured.append("".join(traceback.format_exception(*record.exc_info))[-1800:])


from app import create_app, db  # noqa: E402

fd, path = tempfile.mkstemp()
os.close(fd)
DB_URL = os.environ.get("FUZZ_DB_URL") or f"sqlite:///{path}"
app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": DB_URL, "CSRF_ENABLED": False,
                  "PROPAGATE_EXCEPTIONS": False})
app.logger.addHandler(Capture())
logging.getLogger("werkzeug").setLevel(logging.CRITICAL)
for name in ("serviceops.request", "alembic"):
    logging.getLogger(name).setLevel(logging.CRITICAL)
import load_demo_dataset  # noqa: E402

with app.app_context():
    load_demo_dataset.load_dataset()
    # Project management (B-443): enable it and seed a small project so its
    # pages, forms and API routes are exercised too.
    from app import PlatformSetting, Ticket, User
    from serviceops_core.projects import service as projects
    fuzz_admin = User.query.filter_by(username="admin").one()
    db.session.merge(PlatformSetting(key="PROJECTS_ENABLED", value="true", tenant_id=fuzz_admin.tenant_id))
    fuzz_project = projects.create_project(fuzz_admin, "FZ", "Fuzz project", visibility="open")
    fuzz_epic = projects.create_item(fuzz_admin, fuzz_project, "Fuzz epic", item_type="epic")
    fuzz_story = projects.create_item(fuzz_admin, fuzz_project, "Fuzz story", item_type="story",
                                      parent_id=fuzz_epic.id, assignee_ids=[fuzz_admin.id], labels="fuzz")
    projects.create_item(fuzz_admin, fuzz_project, "Fuzz subtask", item_type="subtask", parent_id=fuzz_story.id)
    projects.add_comment(fuzz_admin, fuzz_story, "Fuzz comment")
    first_ticket = Ticket.query.first()
    if first_ticket:
        projects.add_link(fuzz_admin, fuzz_story, "relates", first_ticket.number)
    db.session.commit()
    from sqlalchemy import inspect, text
    insp = inspect(db.engine)
    ids = defaultdict(list)
    for table in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns(table)}
        if "id" in cols:
            ids[table] = [r[0] for r in db.session.execute(text(f'select id from "{table}" order by id limit 3'))]
    from app import Ticket
    numbers = [t.number for t in Ticket.query.limit(6)]

client = app.test_client()
assert client.post("/login", data={"username": "admin", "password": "Admin123!"}).status_code in (302, 303)
failures = {}


def record(method, url, status, note=""):
    key = (method, re.sub(r"\d+", "N", url.split("?")[0]))
    if key in failures:
        return
    tb = captured[-1] if captured else "(no traceback captured)"
    failures[key] = (status, url, note, tb)


def hit(method, url, **kw):
    note = kw.pop("_note", "")
    before = len(captured)
    try:
        r = client.open(url, method=method, **kw)
    except Exception as error:  # propagated despite PROPAGATE_EXCEPTIONS=False
        import traceback
        captured.append(traceback.format_exc()[-1800:])
        record(method, url, "EXC", type(error).__name__)
        return None
    if r.status_code >= 500 and r.status_code != 503:
        record(method, url, r.status_code, note)
    elif len(captured) > before and r.status_code < 500:
        record(method, url, f"{r.status_code}+logged-error", note)
    return r


all_ids = sorted({i for v in ids.values() for i in v}) or [1]
VALUES = all_ids[:3]


def fill(rule, value):
    url = re.sub(r"<int:\w+>", str(value), rule)
    url = re.sub(r"<number>", numbers[0] if numbers else "INC0000001", url)
    url = url.replace("<key>", "FZ").replace("<item_key>", "FZ-2")
    return re.sub(r"<(?:\w+:)?\w+>", "x", url)


class Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.cur, self.select = [], None, None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.cur = {"action": a.get("action") or "", "method": (a.get("method") or "get").upper(), "fields": []}
            self.forms.append(self.cur)
        elif self.cur is not None and tag in ("input", "textarea", "select") and a.get("name"):
            self.cur["fields"].append((a.get("name"), tag, (a.get("type") or "").lower(), a.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None


GARBAGE = {"number": "abc", "date": "not-a-date", "datetime-local": "2026-99-99T99:99", "email": "x",
           "checkbox": "maybe", "hidden": "zzz", "": "x" * 3000, "nul": "a\u0000b"}
pages = []
if MODE in ("all", "get"):
    for rule in app.url_map.iter_rules():
        if "GET" not in rule.methods or rule.endpoint == "static" or "logout" in rule.rule:
            continue
        if "/stream" in rule.rule:
            continue
        for value in (VALUES if "<" in rule.rule else [None]):
            url = fill(rule.rule, value) if value is not None else rule.rule
            r = hit("GET", url)
            if r is not None and r.status_code == 200 and "text/html" in r.content_type:
                pages.append((url, r.get_data(as_text=True)))
            for q in ("?page=abc&limit=-5&per_page=zz&sort=%27&order=sideways&q=" + "x" * 600,
                      "?cursor=AAAA&offset=-1&filter=%7B&state=%00&start=bad&end=bad&format=nope"):
                hit("GET", url + q)
            if value is None:
                break
    print(f"GET phase: {len(pages)} pages, {len(failures)} failures so far", flush=True)

if MODE in ("all", "forms"):
    if not pages:
        for rule in app.url_map.iter_rules():
            if "GET" in rule.methods and "<" not in rule.rule and rule.endpoint != "static" and "logout" not in rule.rule and "/stream" not in rule.rule:
                r = client.get(rule.rule)
                if r.status_code == 200 and "text/html" in r.content_type:
                    pages.append((rule.rule, r.get_data(as_text=True)))
            elif "GET" in rule.methods and "<int:" in rule.rule:
                r = client.get(fill(rule.rule, VALUES[0]))
                if r.status_code == 200 and "text/html" in r.content_type:
                    pages.append((fill(rule.rule, VALUES[0]), r.get_data(as_text=True)))
    seen = set()
    for url, html in pages:
        parser = Forms()
        parser.feed(html)
        for form in parser.forms:
            action = form["action"] or url
            if not action.startswith("/") or "logout" in action or form["method"] != "POST":
                continue
            key = (action, tuple(sorted(f[0] for f in form["fields"])))
            if key in seen:
                continue
            seen.add(key)
            hit("POST", action, data={})
            for name, tag, typ, _ in form["fields"]:
                if name in ("csrf_token",):
                    continue
                data = {n: v for n, _, _, v in form["fields"]}
                data[name] = GARBAGE.get(typ, GARBAGE[""])
                hit("POST", action, data=data)
                if typ in ("", "text", "search"):
                    data[name] = GARBAGE["nul"]
                    hit("POST", action, data=data)
            client.post("/login", data={"username": "admin", "password": "Admin123!"})  # stay signed in
    print(f"form phase: {len(seen)} forms, {len(failures)} failures so far", flush=True)

if MODE in ("all", "api"):
    api = app.test_client()
    headers = {"X-ServiceOps-App-Version": "1.0", "X-ServiceOps-App-Build": "1", "X-ServiceOps-Platform": "iOS",
               "X-ServiceOps-Device": "fuzz"}
    r = api.post("/api/v1/auth/mobile/login", json={"username": "admin", "password": "Admin123!"}, headers=headers)
    token = r.get_json()["access_token"]
    headers["Authorization"] = f"Bearer {token}"
    headers["Idempotency-Key"] = "fuzz-1"
    client = api
    bodies = [None, "not json", [], {"x": 1}, {"state": 123, "priority": [], "body": {}, "decision": None,
              "parent_id": "abc", "assigned_to_id": "x", "name": 5, "token": 7, "device_id": [],
              "challenge_id": {}, "credential": "x", "refresh_token": 5, "mfa_code": [], "jsonrpc": "2.0",
              "method": "tools/call", "params": "x", "id": 1},
              {k: "y" * 3000 for k in ("title", "description", "body", "name", "state", "priority", "comments",
                                         "resolution_notes", "closure_category", "category", "ci_name",
                                         "token", "device_id", "environment", "userName", "displayName",
                                         "event_id", "summary", "severity", "source", "host", "message")},
              {"title": "a\u0000b", "body": "a\u0000b", "name": "a\u0000b"}]
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith(("/api/v1", "/scim/v2")) or "logout" in rule.rule:
            continue
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            url = fill(rule.rule, VALUES[0])
            for body in bodies:
                headers["Idempotency-Key"] = f"fuzz-{abs(hash((url, method, str(body))))}"
                if body == "not json":
                    hit(method, url, data="{not json", headers=headers, content_type="application/json")
                else:
                    hit(method, url, json=body, headers=headers)
            hit("GET", url + "?limit=abc&cursor=%%%&q=" + "x" * 2000, headers=headers) if method == "GET" else None
    print(f"API phase: {len(failures)} failures so far", flush=True)

if MODE in ("all", "posts"):
    import glob as _glob
    names = set()
    for f in _glob.glob(ROOT + "/templates/**/*.html", recursive=True):
        names |= set(re.findall(r'name="([a-zA-Z_][a-zA-Z0-9_\[\]]*)"', open(f).read()))
    for f in _glob.glob(ROOT + "/static/*.js"):
        names |= set(re.findall(r'append\("([a-zA-Z_][a-zA-Z0-9_]*)"', open(f).read()))
    names.discard("csrf_token")
    print(f"{len(names)} field names", flush=True)
    accounts = [("admin", "Admin123!")]
    with app.app_context():
        from app import User
        for role in ("agent", "requester", "manager"):
            u = User.query.filter_by(role=role, active=True).first()
            if u:
                from serviceops_core.security import hash_password
                u.password_hash = hash_password("Fuzz-Pass-123!")
                accounts.append((u.username, "Fuzz-Pass-123!"))
        db.session.commit()
    rules = [r for r in app.url_map.iter_rules() if "POST" in r.methods and not r.rule.startswith(("/api/", "/scim/"))
             and "logout" not in r.rule and r.endpoint != "static" and "login" not in r.rule and "reset-password" not in r.rule
             and "revoke" not in r.rule and "/sessions" not in r.rule and "erase" not in r.rule and "/delete" not in r.rule]
    for username, password in accounts:
        client = app.test_client()
        client.post("/login", data={"username": username, "password": password})
        for rule in rules:
            for value in (VALUES if "<" in rule.rule else [None]):
                url = fill(rule.rule, value) if value is not None else rule.rule
                hit("POST", url, data={}, _note=username)
                hit("POST", url, data={n: "zzz" for n in names}, _note=username)
                hit("POST", url, data={n: "y" * 3000 for n in names}, _note=username)
                hit("POST", url, data={n: "" for n in names}, _note=username)
                if value is not None and value != VALUES[0]:
                    break
            with client.session_transaction() as sess:
                still = sess.get("_user_id")
            if not still:
                client.post("/login", data={"username": username, "password": password})
        print(f"posts as {username}: {len(failures)} failures so far", flush=True)

print(f"\n=== {len(failures)} distinct failing routes ===")
for (method, shape), (status, url, note, tb) in sorted(failures.items()):
    last = [l for l in tb.strip().splitlines() if l.strip()]
    where = [l.strip() for l in last if l.strip().startswith('File "' + ROOT)]
    print(f"\n[{status}] {method} {url[:140]}  ({note})")
    print("   at:", where[-1][:200] if where else "-")
    print("   ", last[-1][:300] if last else "")
os.unlink(path)
sys.exit(1 if failures else 0)
