"""WebAuthn primitives used by the mobile passkey API.

The HTTP layer owns tenant/user lookup and one-time challenge persistence;
this module keeps protocol generation and cryptographic verification testable.
"""
import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


def registration_options(*, rp_id, rp_name, user, credentials):
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            require_resident_key=True,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=row.credential_id) for row in credentials],
    )
    return options, json.loads(options_to_json(options))


def authentication_options(*, rp_id, credentials=None):
    allowed = None
    if credentials is not None:
        allowed = [PublicKeyCredentialDescriptor(id=row.credential_id) for row in credentials]
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allowed,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options, json.loads(options_to_json(options))


def verify_registration(*, credential, challenge, rp_id, origin):
    return verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        require_user_verification=True,
    )


def verify_authentication(*, credential, challenge, rp_id, origin, stored):
    return verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=stored.public_key,
        credential_current_sign_count=stored.sign_count,
        require_user_verification=True,
    )
