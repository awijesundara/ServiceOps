import pytest

from tools.postgres_migration_rehearsal import assert_downgrade_preserved


def _snapshot(counts):
    return {"counts": counts, "user_digest": "users", "rehearsal_digest": "records"}


def test_downgrade_may_remove_only_empty_head_table():
    assert_downgrade_preserved(
        _snapshot({"user": 3, "new_job": 0}),
        _snapshot({"user": 3}),
    )


def test_downgrade_refuses_to_discard_head_table_rows():
    with pytest.raises(RuntimeError, match="new_job"):
        assert_downgrade_preserved(
            _snapshot({"user": 3, "new_job": 1}),
            _snapshot({"user": 3}),
        )
