from serviceops_core.feature_flags import configured_feature_flags, feature_enabled


def test_feature_flags_are_strict_booleans(monkeypatch):
    monkeypatch.setenv("FEATURE_FLAGS", '{"netbox_sync":false,"unsafe":"false","number":1}')
    assert configured_feature_flags() == {"netbox_sync": False}
    assert feature_enabled("netbox_sync", default=True) is False
    assert feature_enabled("missing", default=True) is True


def test_malformed_feature_flags_fail_to_defaults(monkeypatch):
    monkeypatch.setenv("FEATURE_FLAGS", "not-json")
    assert configured_feature_flags() == {}
    assert feature_enabled("netbox_sync", default=True) is True
