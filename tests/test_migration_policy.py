from pathlib import Path

from tools.verify_migration_safety import verify


def write_migration(tmp_path, body):
    path = tmp_path / "migration.py"
    path.write_text(body)
    return path


def test_expand_migration_rejects_destructive_operations(tmp_path):
    path = write_migration(tmp_path, "serviceops_migration_phase = 'expand'\ndef upgrade():\n    op.drop_column('users', 'name')\n")
    assert "forbidden op.drop_column" in verify(path)[0]


def test_contract_migration_requires_compatibility_version(tmp_path):
    path = write_migration(tmp_path, "serviceops_migration_phase = 'contract'\ndef upgrade():\n    pass\n")
    assert "requires serviceops_contract_after_version" in verify(path)[0]


def test_expand_and_declared_contract_migrations_pass(tmp_path):
    expand = write_migration(tmp_path, "serviceops_migration_phase = 'expand'\ndef upgrade():\n    op.add_column('users', column)\n")
    assert verify(expand) == []
    contract = Path(tmp_path) / "contract.py"
    contract.write_text("serviceops_migration_phase = 'contract'\nserviceops_contract_after_version = '1.81.0'\ndef upgrade():\n    op.drop_column('users', 'legacy')\n")
    assert verify(contract) == []
