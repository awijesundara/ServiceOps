from serviceops_core.config_schema import SETTING_GROUP_META
from serviceops_core.navigation import NAVIGATION_ENTRIES, navigation_entries


def test_navigation_catalogue_has_unique_destinations_and_labels():
    entries = navigation_entries(SETTING_GROUP_META)
    destinations = [(entry.endpoint, tuple(sorted(entry.params.items()))) for entry in entries]
    labels = [entry.label.casefold() for entry in entries]
    assert len(destinations) == len(set(destinations))
    assert len(labels) == len(set(labels))


def test_navigation_catalogue_covers_required_administration_and_client_areas():
    entries = NAVIGATION_ENTRIES
    labels = {entry.label for entry in entries}
    assert {"Administration home", "Users and access", "CMDB and service map", "ServiceOps mobile"} <= labels
    assert {"Client management", "Customer tickets", "Client organizations", "Client contacts"} <= labels
    assert all(entry.client_management for entry in entries if entry.label.startswith("Client ") or entry.label.startswith("Customer "))
