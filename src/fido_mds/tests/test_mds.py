# -*- coding: utf-8 -*-
import pytest

from fido_mds import Attestation, FidoMetadataStore
from fido_mds.tests.data import MICROSOFT_SURFACE_1796, NEXUS_5, YUBIKEY_4, YUBIKEY_5_NFC

__author__ = 'lundberg'


@pytest.mark.parametrize('attestation_obj,client_data', [YUBIKEY_4, YUBIKEY_5_NFC, MICROSOFT_SURFACE_1796, NEXUS_5])
def test_get_metadata_entry(mds: FidoMetadataStore, attestation_obj: str, client_data: str):
    att = Attestation.from_base64(attestation_obj)
    authenticator_id = att.aaguid or att.certificate_key_identifier
    assert authenticator_id is not None

    metadata_entry = mds.get_entry(authenticator_id=authenticator_id)
    assert metadata_entry is not None

    if att.aaguid:
        assert str(att.aaguid) == metadata_entry.aaguid
    elif att.certificate_key_identifier:
        assert metadata_entry.metadata_statement.attestation_certificate_key_identifiers is not None  # please mypy
        assert (
            att.certificate_key_identifier in metadata_entry.metadata_statement.attestation_certificate_key_identifiers
        )


def test_get_user_verification_methods(mds: FidoMetadataStore):
    # alert if new methods are added to the metadata
    user_verification_methods_in_metadata = mds.get_user_verification_methods()
    assert sorted(user_verification_methods_in_metadata) == sorted(
        [
            'presence_internal',
            'fingerprint_internal',
            'voiceprint_internal',
            'location_internal',
            'faceprint_internal',
            'all',
            'eyeprint_internal',
            'passcode_external',
            'pattern_internal',
            'passcode_internal',
            'handprint_internal',
            'none',
        ]
    )


def test_get_key_protections(mds: FidoMetadataStore):
    # alert new values are added to the metadata
    key_protections_in_metadata = mds.get_key_protections()
    assert sorted(key_protections_in_metadata) == sorted(
        ['remote_handle', 'software', 'hardware', 'tee', 'secure_element']
    )


def test_get_crypto_strength(mds: FidoMetadataStore):
    # alert new values are added to the metadata
    crypto_strengths_in_metadata = mds.get_crypto_strengths()
    assert sorted(crypto_strengths_in_metadata) == sorted([128, 256])
