# -*- coding: utf-8 -*-

import pytest
from fido2.utils import websafe_decode

from fido_mds.exceptions import MetadataValidationError
from fido_mds.metadata_store import FidoMetadataStore
from fido_mds.models.webauthn import Attestation
from fido_mds.tests.data import IPHONE_12, MICROSOFT_SURFACE_1796, NEXUS_5, YUBIKEY_4, YUBIKEY_5_NFC

__author__ = "lundberg"


@pytest.mark.parametrize("attestation_obj,client_data", [YUBIKEY_4, YUBIKEY_5_NFC, MICROSOFT_SURFACE_1796])
def test_verify(mds: FidoMetadataStore, attestation_obj: str, client_data: str):
    att = Attestation.from_base64(attestation_obj)
    cd = websafe_decode(client_data)
    assert mds.verify_attestation(attestation=att, client_data=cd) is True


# test attestations with short-lived certs so metadata can't be validated
@pytest.mark.parametrize("attestation_obj,client_data", [IPHONE_12, NEXUS_5])
def test_verify_no_validate(mds: FidoMetadataStore, attestation_obj: str, client_data: str):
    att = Attestation.from_base64(attestation_obj)
    cd = websafe_decode(client_data)
    with pytest.raises(MetadataValidationError):
        mds.verify_attestation(attestation=att, client_data=cd)
