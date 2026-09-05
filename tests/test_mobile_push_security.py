from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from joserfc import jwt
from joserfc.jwk import ECKey

import app as serviceops_app


def test_apns_authorization_token_uses_supported_es256_implementation(monkeypatch):
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    values = {
        "APNS_PRIVATE_KEY": private_pem,
        "APNS_KEY_ID": "TESTKEY01",
        "APNS_TEAM_ID": "TESTTEAM01",
    }
    monkeypatch.setattr(serviceops_app, "setting_value", lambda key, default="": values.get(key, default))

    token = serviceops_app._apns_authorization_token()
    decoded = jwt.decode(token, ECKey.import_key(public_pem), algorithms=["ES256"])

    assert decoded.header["alg"] == "ES256"
    assert decoded.header["kid"] == "TESTKEY01"
    assert decoded.claims["iss"] == "TESTTEAM01"
    assert isinstance(decoded.claims["iat"], int)
