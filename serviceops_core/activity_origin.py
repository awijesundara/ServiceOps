"""Activity attribution from authenticated client identity, never request headers."""
from flask import current_app, g, has_request_context


def activity_origin():
    try:
        if not has_request_context():
            return None
        client = getattr(g, 'api_client', None)
        if client and client.client_kind == 'mobile' and getattr(g, 'api_user', None):
            return 'iOS' if (client.platform or '').lower() == 'ios' else 'Mobile app'
        return None
    except Exception:
        current_app.logger.exception('Activity origin lookup failed')
        raise
