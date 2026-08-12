"""Compatibility tests for the serviceops_core.identity/task_lifecycle/
config_schema bounded interfaces (B-203): each module must import and
behave correctly with zero Flask/database dependency, and the pure logic
extracted out of app.py must be provably identical to what it replaced.
"""
import serviceops_core.config_schema as config_schema
import serviceops_core.identity as identity
import serviceops_core.task_lifecycle as task_lifecycle


# --- identity.py -------------------------------------------------------

def test_ldap_login_local_part_strips_upn_and_down_level_forms():
    assert identity.ldap_login_local_part("jsmith") == "jsmith"
    assert identity.ldap_login_local_part("jsmith@company.com") == "jsmith"
    assert identity.ldap_login_local_part("CORP\\jsmith") == "jsmith"
    # A down-level name containing a literal backslash in the account part
    # (rare, but valid) only strips the first (domain) separator.
    assert identity.ldap_login_local_part("CORP\\dept\\jsmith") == "dept\\jsmith"


def test_ldap_domain_suffix_from_base_dn():
    assert identity.ldap_domain_suffix_from_base_dn(
        "OU=Users,DC=corp,DC=example,DC=com"
    ) == "corp.example.com"
    assert identity.ldap_domain_suffix_from_base_dn("") == ""
    assert identity.ldap_domain_suffix_from_base_dn("OU=Users") == ""


def test_normalized_directory_groups_produces_dn_and_cn_aliases():
    result = identity.normalized_directory_groups(["CN=gg_unix,OU=Groups,DC=example,DC=com"])
    assert "cn=gg_unix,ou=groups,dc=example,dc=com" in result
    assert "gg_unix" in result
    assert identity.normalized_directory_groups(None) == set()
    assert identity.normalized_directory_groups([""]) == set()


def test_match_directory_role_mappings_matches_and_falls_back():
    groups = ["CN=gg_admins,OU=Groups,DC=example,DC=com"]
    mappings = {"gg_admins": "admin", "gg_managers": "manager"}
    matched = identity.match_directory_role_mappings(groups, mappings, "requester")
    assert matched == {"admin": "gg_admins"}

    # No matching group -> falls back to the configured default.
    matched = identity.match_directory_role_mappings([], mappings, "manager")
    assert matched == {"manager": None}

    # Configured default isn't a real role -> falls back to `default`.
    matched = identity.match_directory_role_mappings([], mappings, "not-a-role")
    assert matched == {"requester": None}

    # A mapping to an unrecognized role is silently ignored, not matched.
    groups = ["CN=gg_weird,OU=Groups,DC=example,DC=com"]
    mappings = {"gg_weird": "not-a-role"}
    matched = identity.match_directory_role_mappings(groups, mappings, "requester")
    assert matched == {"requester": None}


# --- task_lifecycle.py ---------------------------------------------------

def test_allowed_states_looks_up_or_falls_back_to_self():
    assert task_lifecycle.allowed_states(task_lifecycle.TICKET_TRANSITIONS, "New") == (
        "New", "In Progress", "Pending", "Resolved", "Cancelled",
    )
    # An unrecognized current state is treated as its own sole allowed state.
    assert task_lifecycle.allowed_states(task_lifecycle.TICKET_TRANSITIONS, "Bogus") == ("Bogus",)


def test_transition_tables_have_no_dangling_target_states():
    """Every state a transition table allows moving *to* must also be a
    valid key in that same table (i.e. a state the record could then move
    on from) -- a target with no outgoing entry would silently strand a
    record there with no lifecycle path forward at all."""
    for table in (
        task_lifecycle.TICKET_TRANSITIONS,
        task_lifecycle.ENTERPRISE_TRANSITIONS,
        task_lifecycle.CATALOG_TASK_TRANSITIONS,
        task_lifecycle.OPERATIONAL_TASK_TRANSITIONS,
    ):
        for source, targets in table.items():
            for target in targets:
                assert target in table, f"{target!r} (from {source!r}) has no outgoing transitions"


def test_build_state_track_marks_done_current_upcoming():
    track = task_lifecycle.build_state_track("incident", "Pending")
    statuses = {step["name"]: step["status"] for step in track}
    assert statuses["New"] == "done"
    assert statuses["In Progress"] == "done"
    assert statuses["Pending"] == "current"
    assert statuses["Resolved"] == "upcoming"


def test_build_state_track_handles_a_state_outside_the_known_order():
    track = task_lifecycle.build_state_track("incident", "SomeLegacyState")
    assert track[-1] == {"name": "SomeLegacyState", "status": "current"}
    assert all(step["status"] == "upcoming" for step in track[:-1])


# --- config_schema.py ----------------------------------------------------

def test_find_setting_definition_finds_across_groups_and_returns_none_for_unknown():
    definition = config_schema.find_setting_definition("LDAP_BASE_DN")
    assert definition is not None
    assert definition["key"] == "LDAP_BASE_DN"
    assert config_schema.find_setting_definition("NOT_A_REAL_SETTING") is None


def test_setting_definitions_every_group_has_meta_and_every_key_is_unique():
    assert set(config_schema.SETTING_DEFINITIONS) == set(config_schema.SETTING_GROUP_META)
    seen = set()
    for group in config_schema.SETTING_DEFINITIONS.values():
        for item in group:
            assert item["key"] not in seen, f"duplicate setting key {item['key']!r}"
            seen.add(item["key"])


def test_coerce_bool_and_coerce_int():
    assert config_schema.coerce_bool("true") is True
    assert config_schema.coerce_bool("YES") is True
    assert config_schema.coerce_bool("0") is False
    assert config_schema.coerce_bool("") is False
    assert config_schema.coerce_int("42") == 42
    assert config_schema.coerce_int("not-a-number", default=7) == 7
    assert config_schema.coerce_int(None, default=3) == 3
