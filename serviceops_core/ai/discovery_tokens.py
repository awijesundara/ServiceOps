"""Signed, short-lived discovery previews; never trust browser-provided model limits."""
import hashlib

from flask import current_app
from itsdangerous import URLSafeTimedSerializer, BadSignature

from serviceops_core.ai.provider import ProviderError
from serviceops_core.localization import tr


def binding(config, key):
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        key.encode(),
        current_app.secret_key.encode(),
        200000,
    ).hex()
    return [config.provider, config.endpoint, digest]


def issue(config, key, profiles, tenant_id, user_id):
    return URLSafeTimedSerializer(current_app.secret_key, salt="ai-model-discovery-v1").dumps(
        {"binding": binding(config, key), "profiles": profiles, "tenant_id": tenant_id, "user_id": user_id})


def verify(token, config, key, tenant_id, user_id):
    try:
        data = URLSafeTimedSerializer(current_app.secret_key, salt="ai-model-discovery-v1").loads(token, max_age=900)
        if (data["binding"] != binding(config, key) or data["tenant_id"] != tenant_id or data["user_id"] != user_id):
            raise ValueError
        profile = data["profiles"][config.model]
        return {**profile, "model": config.model}
    except (BadSignature, KeyError, ValueError, TypeError):
        raise ProviderError(tr("Model discovery expired or no longer matches this connection. Detect models again.")) from None
