# ServiceOps database migrations

Production startup runs `alembic upgrade head` before initialization. Revision
`20260726_0001` either creates a fresh schema or adopts a complete existing
ServiceOps schema without rewriting operational data.

The baseline downgrade deliberately fails because deleting an adopted database
is not a safe rollback. Later schema revisions must provide a reversible
one-revision downgrade and verification queries. Removing the baseline requires
restoring the validated pre-migration backup.
