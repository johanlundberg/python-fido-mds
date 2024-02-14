# -*- coding: utf-8 -*-
__author__ = "lundberg"

from dataclasses import dataclass, field
from datetime import datetime
from typing import Union, Optional, List, Set
from uuid import UUID

from fido_mds import FidoMetadataStore
from fido_mds.models.fido_mds import AuthenticatorStatus
from fido_mds.models.webauthn import AttestationFormat


@dataclass
class AuthenticatorInformation:
    authenticator_id: Union[UUID, str]
    attestation_formats: List[AttestationFormat]
    status: Optional[AuthenticatorStatus] = field(default=None)
    last_status_change: Optional[datetime] = field(default=None)
    icon: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    key_protection: list[str] = field(default_factory=list)
    user_verification_methods: list[str] = field(default_factory=list)


WEBAUTHN_ALLOWED_USER_VERIFICATION_METHODS: list[str] = [
    "faceprint_internal",
    "passcode_external",
    "passcode_internal",
    "handprint_internal",
    "pattern_internal",
    "voiceprint_internal",
    "fingerprint_internal",
    "eyeprint_internal",
]
WEBAUTHN_ALLOWED_KEY_PROTECTION: list[str] = ["remote_handle", "hardware", "secure_element", "tee"]

WEBAUTHN_ALLOWED_STATUS: list[AuthenticatorStatus] = [
    AuthenticatorStatus.FIDO_CERTIFIED,
    AuthenticatorStatus.FIDO_CERTIFIED_L1,
    AuthenticatorStatus.FIDO_CERTIFIED_L2,
    AuthenticatorStatus.FIDO_CERTIFIED_L3,
    AuthenticatorStatus.FIDO_CERTIFIED_L1plus,
    AuthenticatorStatus.FIDO_CERTIFIED_L2plus,
    AuthenticatorStatus.FIDO_CERTIFIED_L3plus,
]

mds = FidoMetadataStore()
parsed_entries: List[AuthenticatorInformation] = []
available_status: Set[str] = set()
available_user_verification_methods: Set[str] = set()
available_key_protections: Set[str] = set()


def is_authenticator_mfa_approved(authenticator_info: AuthenticatorInformation) -> bool:
    """
    This is our current policy for determine if a FIDO2 authenticator can do multi-factor authentications.
    """
    print(f"Checking mfa approved for {authenticator_info.description}")
    # If there is no attestation we can not trust the authenticator info
    if not authenticator_info.attestation_formats:
        return False

    # check status in metadata and disallow uncertified and incident statuses
    if authenticator_info.status not in WEBAUTHN_ALLOWED_STATUS:
        print(f"status {authenticator_info.status} is not mfa capable")
        return False

    # true if the authenticator supports any of the user verification methods we allow
    is_accepted_user_verification = any(
        [
            method
            for method in authenticator_info.user_verification_methods
            if method in WEBAUTHN_ALLOWED_USER_VERIFICATION_METHODS
        ]
    )
    # a typical token has key protection ["hardware"] or ["hardware", "tee"] but some also support software, so
    # we have to check that all key protections supported is in our allow list
    is_accepted_key_protection = all(
        [
            protection
            for protection in authenticator_info.key_protection
            if protection in WEBAUTHN_ALLOWED_KEY_PROTECTION
        ]
    )
    print(f"is_accepted_user_verification: {is_accepted_user_verification}")
    if not is_accepted_user_verification:
        print(f"user verification methods: {authenticator_info.user_verification_methods}")
    print(f"is_accepted_key_protection: {is_accepted_key_protection}")
    if not is_accepted_key_protection:
        print(f"key protections: {authenticator_info.key_protection}")
    if is_accepted_user_verification and is_accepted_key_protection:
        return True
    return False


for metadata_entry in mds.metadata.entries:
    last_status_change = metadata_entry.time_of_last_status_change
    user_verification_methods = [
        detail.user_verification_method for detail in metadata_entry.metadata_statement.get_user_verification_details()
    ]
    available_status.add(metadata_entry.status_reports[0].status)
    available_user_verification_methods.update(user_verification_methods)
    available_key_protections.update(metadata_entry.metadata_statement.key_protection)

    authenticator_info = AuthenticatorInformation(
        attestation_formats=metadata_entry.metadata_statement.attestation_types,
        authenticator_id=metadata_entry.aaguid or metadata_entry.aaid,
        status=metadata_entry.status_reports[0].status,  # latest status reports status
        last_status_change=last_status_change,
        user_verification_methods=user_verification_methods,
        key_protection=metadata_entry.metadata_statement.key_protection,
        description=metadata_entry.metadata_statement.description,
        # icon=metadata_entry.metadata_statement.icon,
    )
    parsed_entries.append(authenticator_info)

approved = 0
for entry in parsed_entries:
    print()
    if is_authenticator_mfa_approved(entry):
        approved += 1
        print(entry)


print()
print(f"{len(parsed_entries)} authenticators parsed, {approved} approved, {len(parsed_entries) - approved} rejected")
print(f"Available statuses: {available_status}")
print(f"Available user verification methods: {available_user_verification_methods}")
print(f"Available key protections: {available_key_protections}")
print()
used_status = [item.value for item in WEBAUTHN_ALLOWED_STATUS]
print(f"Unused statuses: {available_status - set(used_status)}")
print(
    f"Unsued user verification methods: {available_user_verification_methods - set(WEBAUTHN_ALLOWED_USER_VERIFICATION_METHODS)}"
)
print(f"Unused key protections: {available_key_protections - set(WEBAUTHN_ALLOWED_KEY_PROTECTION)}")
