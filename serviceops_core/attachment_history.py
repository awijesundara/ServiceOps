"""Durable comment attachment notices from append-only ticket deletion events."""
import json
from collections import defaultdict
from flask import current_app


def deleted_comment_attachments(history):
    """Group new-format deletion events; legacy events have no comment link."""
    try:
        result = defaultdict(list)
        for event in history:
            if event.event != 'Attachment deleted' or not event.old_value:
                continue
            try:
                metadata = json.loads(event.old_value)
            except (ValueError, TypeError):
                current_app.logger.warning('Invalid attachment deletion metadata on event %s', event.id)
                continue
            if not isinstance(metadata, dict) or metadata.get('schema_version') != 1:
                current_app.logger.warning('Unsupported attachment deletion metadata on event %s', event.id)
                continue
            if not isinstance(metadata.get('attachment_id'), int) or not all(isinstance(metadata.get(key), str) for key in ('name', 'reason')):
                current_app.logger.warning('Incomplete attachment deletion metadata on event %s', event.id)
                continue
            comment_id = metadata.get('comment_id')
            if isinstance(comment_id, int) and not isinstance(comment_id, bool):
                result[comment_id].append({
                    'id': metadata['attachment_id'], 'name': metadata['name'],
                    'reason': metadata['reason'], 'deleted_at': event.created_at.isoformat(),
                    'deleted_by': event.actor.name if event.actor else None,
                })
        return dict(result)
    except Exception:
        current_app.logger.exception('Deleted comment attachment projection failed')
        raise
