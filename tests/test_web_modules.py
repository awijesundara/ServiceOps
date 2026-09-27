"""Route modules in serviceops_core/web/ (B-401): app.create_app() wires them
up but defines no routes itself, and every module registers into one app
without clashing endpoint names."""
import ast
from pathlib import Path

from tests.test_app import app  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parent.parent
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}


def route_handlers(path):
    handlers = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS \
                        and isinstance(target.value, ast.Name) and target.value.id == "app":
                    handlers.append(node.name)
                    break
    return handlers


def test_app_py_defines_no_routes():
    assert route_handlers(ROOT / "app.py") == [], (
        "Add new routes to the matching module in serviceops_core/web/, not app.py"
    )


def test_every_web_module_registers_routes_and_endpoints_are_unique():
    modules = sorted(p for p in (ROOT / "serviceops_core" / "web").glob("*.py")
                     if p.name not in ("__init__.py", "common.py"))
    names = []
    for module in modules:
        handlers = route_handlers(module)
        assert handlers, f"{module.name} registers no routes"
        names.extend(handlers)
    assert len(names) == len(set(names))


def test_registered_app_serves_every_module(app):
    endpoints = set(app.view_functions)
    for module in sorted((ROOT / "serviceops_core" / "web").glob("*.py")):
        handlers = route_handlers(module)
        if handlers:
            assert set(handlers) & endpoints, f"{module.name} routes are not registered"
