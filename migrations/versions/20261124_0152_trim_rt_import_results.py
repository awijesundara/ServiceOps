"""Trim oversized RT import job results.

Results stored by imports before 1.114.15 were not capped (every preview row and error of every
ticket) and could reach tens of megabytes; the import page loaded and parsed them repeatedly and the
web worker was OOM-killed. Rows larger than 1 MB are rewritten, one at a time, to their counts plus
the first 100 errors and preview rows.

Revision ID: 20261124_0152
Revises: 20261031_0151
"""
import json
import re

import sqlalchemy as sa
from alembic import op

revision = "20261124_0152"
down_revision = "20261031_0151"
branch_labels = None
depends_on = None

LIMIT = 1024 * 1024
KEEP = 100
COUNTS = ("tickets_seen", "records_created", "events_created", "changes_created", "already_imported",
          "teams_created", "users_created", "comments_imported", "attachments_imported")


def upgrade():
    bind = op.get_bind()
    jobs = sa.table("rt_import_job", sa.column("id", sa.Integer), sa.column("result_json", sa.Text))
    large = bind.execute(sa.select(jobs.c.id).where(sa.func.length(jobs.c.result_json) > LIMIT)).scalars().all()
    for job_id in large:
        text = bind.execute(sa.select(jobs.c.result_json).where(jobs.c.id == job_id)).scalar()
        try:
            result = json.loads(text)
            trimmed = {key: value for key, value in result.items() if not isinstance(value, list)}
            for key in ("errors", "preview"):
                items = result.get(key) if isinstance(result.get(key), list) else []
                trimmed[key] = items[:KEEP]
                trimmed[key + "_total"] = len(items)
        except (ValueError, AttributeError, MemoryError):
            trimmed = {key: int(m.group(1)) for key in COUNTS
                       for m in [re.search(rf'"{key}"\s*:\s*(\d+)', text[:4000])] if m}
            trimmed.update(errors=[], preview=[], truncated=True)
        bind.execute(jobs.update().where(jobs.c.id == job_id).values(result_json=json.dumps(trimmed)))
        del text


def downgrade():
    pass  # trimmed detail cannot be restored
