"""Shared pytest setup: browser artifact capture and fast test password hashes."""

import pytest
import werkzeug.security

# Test fixtures create many users with werkzeug's generate_password_hash, whose
# scrypt default costs ~0.1 s per hash and per login. Test passwords protect
# nothing, so use a cheap PBKDF2 setting; verification reads the method from
# each stored hash, so production hashes and code paths are unaffected.
_generate_password_hash = werkzeug.security.generate_password_hash


def _fast_generate_password_hash(password, method="pbkdf2:sha256:1000", salt_length=16):
    return _generate_password_hash(password, method=method, salt_length=salt_length)


werkzeug.security.generate_password_hash = _fast_generate_password_hash


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    setattr(item, f"rep_{report.when}", report)
