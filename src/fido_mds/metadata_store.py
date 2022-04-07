# -*- coding: utf-8 -*-
import logging
from importlib import resources
from pathlib import Path
from typing import Optional, Dict, Union
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import (
    Version,
    NameOID,
    BasicConstraints,
    ObjectIdentifier,
    ExtensionNotFound,
    UnrecognizedExtension,
    Certificate,
)
from fido2 import cbor
from fido2.ctap2 import AttestationObject
from fido2.utils import websafe_decode, int2bytes
from iso3166 import countries_by_alpha2

from fido_mds.helpers import get_cose_alg, cert_chain_verified, load_raw_cert
from fido_mds.models.fido_mds import FidoMD, Entry

__author__ = 'lundberg'

from fido_mds.models.webauthn import Attestation, AttestationFormat

logger = logging.getLogger(__name__)


class ValidationError(ValueError):
    pass


class FidoMetadataStore:
    def __init__(self, metadata_path: Optional[Path] = None):
        # default to bundled metadata
        if metadata_path is not None:
            try:
                with open(metadata_path, 'r') as f:
                    self.metadata = FidoMD.parse_raw(f.read())
            except IOError as e:
                logger.error(f'Could not open file {f}: {e}')
        else:
            with resources.open_text('fido_mds.data', 'metadata.json') as f:
                self.metadata = FidoMD.parse_raw(f.read())

        self.external_root_certs: Dict[str, Certificate] = {}
        # load known external root certs
        with resources.open_binary('fido_mds.data', 'apple_webauthn_root_ca.pem') as f:
            self.add_external_root_cert(name='apple', root_cert=f.read())
        self._aaguid_cache: Dict[UUID, Entry] = {}

    def add_external_root_cert(self, name: str, root_cert: Union[bytes, str]):
        self.external_root_certs[name] = load_raw_cert(cert=root_cert)

    def get_entry_for_aaguid(self, aaguid: UUID) -> Optional[Entry]:
        if aaguid in self._aaguid_cache:
            return self._aaguid_cache[aaguid]

        for entry in self.metadata.entries:
            if entry.aaguid is not None and UUID(entry.aaguid) == aaguid:
                self._aaguid_cache[aaguid] = entry
                return entry
        return None

    def verify_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        if attestation.fmt is AttestationFormat.PACKED:
            return self.verify_packed_attestation(attestation=attestation, client_data=client_data)
        if attestation.fmt is AttestationFormat.APPLE:
            return self.verify_apple_anonymous_attestation(attestation=attestation, client_data=client_data)
        if attestation.fmt is AttestationFormat.TPM:
            return self.verify_tpm_attestation(attestation=attestation, client_data=client_data)
        raise NotImplementedError(f'verification of {attestation.fmt.value} not implemented')

    def verify_packed_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        # if there is a cert chain it is a FULL packed attestation
        if not attestation.att_statement.x5c:
            raise NotImplementedError('packed SELF(SURROGATE) or ECDAA attestations not implemented')

        # first cert in chain is the one we want to check
        leaf_cert = attestation.att_statement.x5c[0]

        # version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
        logger.debug(f'cert version: {leaf_cert.version}')
        if leaf_cert.version != Version.v3:
            raise ValidationError(f'certificate version {leaf_cert.version} != {Version.v3}')

        # Subject-C MUST be a ISO 3166 code specifying the country where the Authenticator vendor is incorporated
        country_code = leaf_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
        logger.debug(f'cert country code: {country_code}')
        if country_code not in countries_by_alpha2:
            raise ValidationError(f'country (C) {country_code} is not a recognized country code')

        # Subject-O MUST be legal name of the Authenticator vendor
        organisation_name = leaf_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        logger.debug(f'cert organization name: {organisation_name}')
        if not organisation_name:
            raise ValidationError(f'certificate subject organisation (O) is missing')

        # Subject-OU MUST be literal string “Authenticator Attestation”
        organization_unit = leaf_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        logger.debug(f'cert organization unit name: {organization_unit}')
        if organization_unit != 'Authenticator Attestation':
            raise ValidationError(f'certificate subject organisation unit (OU) is not "Authenticator Attestation"')

        # Subject-CN MUST not be empty
        common_name = leaf_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        logger.debug(f'cert common name: {common_name}')
        if not common_name:
            raise ValidationError(f'certificate common name (CN) is missing')

        # check that cert basic constraints for CA is set to False
        basic_constraints = leaf_cert.extensions.get_extension_for_class(BasicConstraints).value
        logger.debug(f'cert basic constraints ca: {basic_constraints.ca}')
        if basic_constraints.ca is not False:
            raise ValidationError(f'cert basic constraints ca must be False')

        # if certificate contains id-fido-gen-ce-aaguid extension, then check that its value set to the
        # AAGUID returned by the authenticator in authData
        ID_FIDO_GEN_CE_AAGUID_OID = ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4')
        id_fido_gen_ce_aaguid = None
        try:
            id_fido_gen_ce_aaguid_ext = leaf_cert.extensions.get_extension_for_oid(ID_FIDO_GEN_CE_AAGUID_OID)
            if isinstance(id_fido_gen_ce_aaguid_ext, UnrecognizedExtension):
                # cryptography does not know the extension, create UUID from the bytes in value
                b_aaguid = id_fido_gen_ce_aaguid_ext.value
                # see https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
                if len(b_aaguid) == 18 and b_aaguid[:2] == b'\x04\x10':
                    id_fido_gen_ce_aaguid = UUID(bytes=b_aaguid[2:])
                else:
                    raise ValidationError('Could not parse AAGUID from certificate extension')
        except ExtensionNotFound:
            # If the related attestation root certificate is used for multiple authenticator models,
            # the Extension id-fido-gen-ce-aaguid MUST be present
            # TODO: Should we make a check for this?
            pass
        if id_fido_gen_ce_aaguid is not None:
            logger.debug(f'cert id_fido_gen_ce_aaguid extension: {id_fido_gen_ce_aaguid}')
            if id_fido_gen_ce_aaguid != attestation.auth_data.credential_data.aaguid:
                raise ValidationError(
                    f'cert id_fido_gen_ce_aaguid extension {id_fido_gen_ce_aaguid} does'
                    f' not match {attestation.auth_data.credential_data.aaguid}'
                )
        # concatenate authData with clientDataHash to create signatureBase and verify that using cert public key
        cose_alg = get_cose_alg(attestation.att_statement.alg)
        client_data_hash = cose_alg.hash(data=client_data)
        signature_base = attestation.raw_auth_data + client_data_hash
        if not cose_alg.verify(
            key=leaf_cert.public_key(), signature=attestation.att_statement.sig, data=signature_base
        ):
            raise ValidationError('signature does not match data')

        # validata leaf cert again root cert in metadata
        metadata_entry = self.get_entry_for_aaguid(aaguid=attestation.auth_data.credential_data.aaguid)
        root_certs = [
            load_raw_cert(root_cert) for root_cert in metadata_entry.metadata_statement.attestation_root_certificates
        ]
        if not cert_chain_verified(cert_chain=attestation.att_statement.x5c, root_certs=root_certs):
            raise ValidationError('metadata root cert does not match attestation cert')

        return True

    def verify_apple_anonymous_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        if not attestation.att_statement.x5c:
            raise ValidationError('no cert chain found in attestation')

        # first cert in chain is the one we want to check
        leaf_cert = attestation.att_statement.x5c[0]

        # concatenate authenticator data and SHA-256 hash of client data to form nonce base
        client_data_hash = hashes.Hash(SHA256())
        client_data_hash.update(data=client_data)
        nonce_base = attestation.raw_auth_data + client_data_hash.finalize()

        # perform SHA-256 hash of nonce base to produce nonce
        nonce_hash = hashes.Hash(SHA256())
        nonce_hash.update(nonce_base)
        expected_nonce = nonce_hash.finalize()

        # check that certificate contains AppleAnonymousAttestation OID 1.2.840.113635.100.8.2 extension
        APPLE_NONCE_EXTENSION_OID = ObjectIdentifier('1.2.840.113635.100.8.2')
        try:
            apple_nonce_ext = leaf_cert.extensions.get_extension_for_oid(APPLE_NONCE_EXTENSION_OID)
            apple_nonce = apple_nonce_ext.value.value  # type: ignore
            # verify that expected_nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in leaf cert
            # remove the 6 first bytes as that is just structure
            # see https://medium.com/webauthnworks/webauthn-fido2-verifying-apple-anonymous-attestation-5eaff334c849
            if len(apple_nonce) != 38 or apple_nonce[6:] != expected_nonce:
                raise ValidationError('Apple nonce does not match attestation')
        except ExtensionNotFound:
            raise ValidationError('Apple nonce certificate extension not found')

        # verify that the credential public key equals the Subject Public Key of leaf cert
        cose_cert_pub = attestation.auth_data.credential_data.public_key.from_cryptography_key(leaf_cert.public_key())
        if attestation.auth_data.credential_data.public_key != cose_cert_pub:
            raise ValidationError('credential data public key does not match cert subject public key')

        # validata leaf cert against Apple root cert
        if not cert_chain_verified(
            cert_chain=attestation.att_statement.x5c, root_certs=[self.external_root_certs['apple']]
        ):
            raise ValidationError('metadata root cert does not match attestation cert')
        return True

    def verify_tpm_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        # FIDO2 support only version 2.0
        if attestation.att_statement.ver != "2.0":
            raise ValidationError(f'attestation statement version {attestation.att_statement.ver} is not 2.0')
        # verify cert_info
        # magic must be TPM_GENERATED (0xFF544347)
        if attestation.att_statement.cert_info[0:4] != int2bytes(0xFF544347):
            raise ValidationError('wrong magic in certInfo')
        debug = 1


md = FidoMetadataStore()
# print(md.metadata.json())

# orange yubikey
yubikey_4 = 'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgUHqDeN8I0KSrvYbA5eQ_g_csqzOgY8Rfmwtnn_94i-ECIQCuKt86sg6jgTf0EVUlSqHjcLcLce5X65fF5jIDxx8pHGN4NWOBWQJIMIICRDCCAS6gAwIBAgIEVWK-oDALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE0MzI1MzQ2ODgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARLMx93PYFEuZlcvkWFUX4XWDqkdiNpXL6FrEgsgBnyyblGeuBFsOZvExsuoyQ8kf2mAuMY8_xdjSp6uucr0UMJozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNTATBgsrBgEEAYLlHAIBAQQEAwIFIDALBgkqhkiG9w0BAQsDggEBAKwW2bNutrOpt211lLNPWfT3PtvJ_espNetrRRyr9B0l0-cWFNdHJgTKcqV44yPtt2AEaF8F59G5vgXbbpRA-sXPyTKmyvroUpl3LtsCeCAgPNQUHT7rb2os6Z45V4AyY6urjW7EgKffCErSy6e31td8lMPrwLFm-WBXyvX-OmMeompDN2Kjb77PTPRFCWJf1a8QSap8i8dommZZ6a9d6PDXLCiCUXTFDgarf2oHkIN7bbMqv9y8qDXLuwkO8fDZnghpv-nlZ2TEIw5sBXcpsBDeDsX5zOTJHCgmIY6oCBq7lpFR7BZyWvKo2V53lbyqInqblEMgxCdhnKr4VNmCmNdoYXV0aERhdGFYxNz3BHEmKmoM4iTRAmMUgSjEdNSeKZskhyDzwzPuNmHTQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEBUxM3Zkcq64TUqrXr2nh7urP1cRiwmeX5tyGj22YmQTvRu5z8c-wrptwqJ6Gef15JjZGvkb6epX-6ANI7MNC57pQECAyYgASFYIChWSEnPLFGZFdeiujDUrDRE8YkL5sYM-i_mDgC2QtBPIlgg5vKsrM8Z7fI5rJAiZBVVftNMjiVIX56mKsf6eCZZgU0'
yubikey_4_client_data = 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicUUyQi1FQ25ZRHhuRXZlbzVIVmQ0ZjFxVUotNnhkbU9oNHFIenAtSnI2TSIsIm9yaWdpbiI6Imh0dHBzOi8vZGFzaGJvYXJkLmVkdWlkLmRvY2tlciIsImNyb3NzT3JpZ2luIjpmYWxzZX0'
yubikey_4_credential_id = 'VMTN2ZHKuuE1Kq169p4e7qz9XEYsJnl-bcho9tmJkE70buc_HPsK6bcKiehnn9eSY2Rr5G-nqV_ugDSOzDQuew'


yubico_security_key = 'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAOy8_rzA7xpWVGMoc_0JeB-lqCY_sFygaeajB0fG8XpzAiBsb5ZSbuivkHIkh0RaPs2S_xMZyqg7a_Y9uqmnDrOzcGN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjE3PcEcSYqagziJNECYxSBKMR01J4pmySHIPPDM-42YdNBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQG_jkwdob5C0DyOrfU5xbbdwa3o-9YXYv-m7RkoSuQwEBYNA4HWgPc64doYQPfpH51hKviKieGyKyudKgoOx0tWlAQIDJiABIVggJqHVYvUJM0ZuzlrZ3X98czBnZIKXf-6ijfFGDKqLACEiWCBPAxtczXxLIGHjjiag21Skr16YH8ajF9n7QwcNXhyx0A'
yubico_security_key_att = Attestation.from_base64(yubico_security_key)
print(yubico_security_key_att)


yubikey_5_nfc_attestation_obj = 'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIRbB2kR7PfC27xsxNGePmQcKA_LIRaK0Q0HYX2kVPj5AiEAjL4P92FwUidaVAKfT_mSuH5v0maMshUMRtlxzJZ017RjeDVjgVkCwTCCAr0wggGloAMCAQICBB6PhzQwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDUxMjcyMjc0MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKh5-CM47RSUusBwS8x_xmPRsnFxWXYkMQHHYFEV18FSnigcHGcyLThLXNVd0-mBjV_YXCKvMm4MZPwgr-M_I2ajbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEC_AV5-BE0fqsRa7Wo25ICowDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAhpP_Yt8NV3nUdI1_yNECJzGKjlgOajpXwQjpTgPDhWizZolPzlYkvko-_X80EYs9mTdD95KhmJFgyPya4LBOPfnuFePojAT8gqjcv1gY4QjcwpaFd655_2YrlHNOPexFlzBdc-blXuK-uc2WeMoJNeUz62OPjib6u4F82kQfvpgxgyrl9uKtmS-eu9tMYiOLj416tIHW0yY7zb-eSldVA3CYitWBNED6AyyttnI8rdj417qAn3W0PP-gpbmt0UIy752eFIEmOCM8TKSoc7n4rJjjK6GRZ2BuFZCfzdtKLf-9rkYgJJ-aZkasgeSDLREZ_r-qcxqILaJad4J9RtGQF2hhdXRoRGF0YVjE3PcEcSYqagziJNECYxSBKMR01J4pmySHIPPDM-42YdNBAAAAAS_AV5-BE0fqsRa7Wo25ICoAQDjqf6lUSwig_VinV7E7AHW5-gRqhriPK_Z08Am10wQyl5n6uZ7yWrmNKMd3ASnTuQLZJBQ87gmnVg4N7AU6e1qlAQIDJiABIVggy6WcmMhq0lbHKQMCpHf8D2dczddOstIL5Uld0xzu5Z0iWCD5mY6aAZFwPV-KnwpPi7oiP22CGfqiOvLnLTt9RCCYuA'
yubikey_5_nfc_client_data = 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMlpLQ1NDMWRCOU1CbnBqWGZoLXhYNDBmM3dCXzFCLXM1U0hEMFlNU001QSIsIm9yaWdpbiI6Imh0dHBzOi8vZGFzaGJvYXJkLmVkdWlkLmRvY2tlciIsImNyb3NzT3JpZ2luIjpmYWxzZX0'
print(websafe_decode(yubikey_5_nfc_client_data))
yubikey_5_nfc_credential_id = 'OOp_qVRLCKD9WKdXsTsAdbn6BGqGuI8r9nTwCbXTBDKXmfq5nvJauY0ox3cBKdO5AtkkFDzuCadWDg3sBTp7Wg'
yubikey_5_nfc_att = Attestation.from_base64(yubikey_5_nfc_attestation_obj)
print(yubikey_5_nfc_att)
yubikey_5_nfc_verified = md.verify_attestation(
    attestation=yubikey_5_nfc_att, client_data=websafe_decode(yubikey_5_nfc_client_data)
)
print(f'yubikey_5_nfc: {yubikey_5_nfc_verified}')

iphone_attestation_object = 'o2NmbXRlYXBwbGVnYXR0U3RtdKFjeDVjglkCRjCCAkIwggHJoAMCAQICBgGAA5HWJDAKBggqhkjOPQQDAjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIyMDQwNjEwMjg1MFoXDTIyMDQwOTEwMjg1MFowgZExSTBHBgNVBAMMQGMwNTg5OGNhNTUwMThiMmJkNzI0YzU4NjQ3ZDBkYTczMzlkYjY2MTdhZWU0NzY4OTliMmU4ZTJmMWFhYTAwYWYxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWAO-hvjy7UiAR1hniqYu6Ssa8CFRu1F_UXtByeuhgnU9QBJ0FahxJR2FqTj6yMLRrOAEDjch-JEIxOzaJj2i2KNVMFMwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCBPAwMwYJKoZIhvdjZAgCBCYwJKEiBCDZbFxjinp9DpyOE8E4vmgndGsjMDRJahM1WHHzdN1V4TAKBggqhkjOPQQDAgNnADBkAjBV-Px342-7WTPTyOIr4PfqZAVvEvhbREKLCx2q6F7icGxCZoD5wroStrCM9Ot3UhQCME5XzY_4MsVejH-XF15jbgPoYdKw4HGjRNx6agX4VwIcgkEFk08XpdmpLTiESOrsc1kCODCCAjQwggG6oAMCAQICEFYlU5XHp_tA6-Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz_LBFvHNZk0df1UkETfm_4ZIRdlxpod2gULONRQg0AaQ0-yTREtVsPhz7_LmJH-wGlggb75bLx3yI3dr0alruHdUVta-quTvpwLJpGjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT_oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl-tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz-Wbw00pMMFIeFHZYO1qdfHrSsq-OM0luJfQyAW-8Mf3iwelccboDgdoYXV0aERhdGFYmMY-yg23lncBLbnB_IQLgUnhjmcR07HUho1A5EcRGCzCRQAAAADySo5w0NP4LCk3MlI8xN5aABT5M6rzbtbX60djPMKeuG81NQaRzqUBAgMmIAEhWCBYA76G-PLtSIBHWGeKpi7pKxrwIVG7UX9Re0HJ66GCdSJYID1AEnQVqHElHYWpOPrIwtGs4AQONyH4kQjE7NomPaLY'
iphone_client_data_json = 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRzdGS1l4NmVrZF9NcTJWVW9GcURObV84RmxvYUJJSEZaZE9saXZUcDlXYyIsIm9yaWdpbiI6Imh0dHBzOi8vZGFzaGJvYXJkLmRldi5lZHVpZC5zZSJ9'
iphone_anonymous_att = Attestation.from_base64(iphone_attestation_object)
iphone_verified = md.verify_attestation(
    attestation=iphone_anonymous_att, client_data=websafe_decode(iphone_client_data_json)
)
print(f'iphone: {iphone_verified}')


tpm_attestation_object = 'o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQADKC9cEAtzensGrFGu1yxc9b-MXY-ypayZ1XK-ccAURoqwM8mdCqZ9IvCwskTlRZwnIIlKAPDHejenmoJNLcarMmYAZH9iEj6iuXHjkpjRdVQ_kTsGntT_L8XStSafstiK2WMkyAnxK0E4Dg-i6Mzy_93Uoz0qM8MmZVjrbR3QEEmmuVkLTQ7_QsfId2b3GbdtP-17T7rboUHnhtb-e5CQrcZFNgHeclC1KN1Z9TTM1Tw4p2GZUXYODD-Cx5LZ9nta4vlwx6zaU__RLfjFy4891Jvn9c15H_k8a_S3i4bUn7hUhgQHsNdRVBoYGOU43C3TFuqlvVPsCO56TD3sJV8_Y3ZlcmMyLjBjeDVjglkFtTCCBbEwggOZoAMCAQICED0bYHWxrkPymzCD2iNuX74wDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLU5UQy1LRVlJRC0xNTkxRDRCNkVBRjk4RDAxMDQ4NjRCNjkwM0E0OEREMDAyNjA3N0QzMB4XDTIxMTExNjA4NTcyMVoXDTI3MDYwMzE3NTE0OVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANHM9NQdZwbri22CtYkLJ4HftI9Op2mO1mEc35VWI384Su8QDH9YItYoJnEi-4QS-fPca9T1Ssdf0QnkIKBbb8BaoxbuMucnPoK9BvOR9UBcTBvpFkjkBb1b880HF2Eti6oIyiP92oGyUBCQVmMEjcZIXI1i2T0U8RKnEsjTyG3AwxVvjoSwWwqRhCNC3ZGvtGTEJ2Tz2Gv8PjUMFSI4_1J9_niuEJpeYMJHLZjtcxE6lYObh-enbscsHpcsN5qeAxn3fdAiS8pxUanT-sZdYxEDzip-PRoafT3b7T5DdAm8gIJ0_uooh60dK_6JED6C0eeNrCJcZzD2uIfel6AZ1t0CAwEAAaOCAeQwggHgMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMEoGA1UdEQEB_wRAMD6kPDA6MTgwDgYFZ4EFAgMMBWlkOjEzMBAGBWeBBQICDAdOUENUNnh4MBQGBWeBBQIBDAtpZDo0RTU0NDMwMDAfBgNVHSMEGDAWgBR27Ef3V-wqXtQOHZgCXhTLKFHirTAdBgNVHQ4EFgQUFtCPLIh2MHWSt8ofBNmKmu6LIAkwgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1udGMta2V5aWQtMTU5MWQ0YjZlYWY5OGQwMTA0ODY0YjY5MDNhNDhkZDAwMjYwNzdkMy83ZDJlOWRhMC1mZDhjLTQwY2QtODQxMC0wNGNiMDMyZTAwYWMuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAs7jfTufKDlnLNHUhv59U-MEWvhcfQshDwAvmO7oNWG73Y5Moah0Ki7SczPglvgAvmmTNWKqBcP9ll-SLdGD-qkDYTNJqG0DUsEt9ngdR7_4ZpwOsJCvt_SNg44fESU3d8nTsXGkwfbuyODPH-C_yk85LM0Pnf3q-SxZBINqe-XhvIkK7jWdgj2SHM6vcpvaD4ohpNhe1JFTqGXl4BVOplzy43Vc-vERXD_YAbmXTnMD-RUZC4JjC_hbHMEgxHHwTlTxg_HuqL-rA33-N1ligUQ_vKxrCqJ4XSP3svEDAh72_2ljyPPxO56ZT4DA8y1zWAQxRcG58VArA4MxjT7o8GbGVokcdYJOvD62NbpG9IuRQb763sCZmn_n893dyneX09H6jm97S86S0dghLyx45FHesUueW_ZZMS0xRVKQuTYjv58JDosNYHwvbeDZZlmxQnOaU6usuZoDTHZXPzvMU5m9r6vGpUvrYPSyupK90qOgW61_YLrqXw3naF3-E_vvVKSiiIhCpo6R3lh066kKkDnYL35-OGrODuwTdytmOAF8G1YpH__S4JMcYWu0Bc-HXysH2TqyYu_-_MRVtacTkdrbehdo3x0C_ztQJEXPfZB1f4BzharRrgpJcG5D9s4FMTK0yQRzmTMVwITm8jselKddHbdJHoI5BPvVsQf1AxSVkG7zCCBuswggTToAMCAQICEzMAAAQJFK8U1c8A0ecAAAAABAkwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMTA2MDMxNzUxNDlaFw0yNzA2MDMxNzUxNDlaMEExPzA9BgNVBAMTNkVVUy1OVEMtS0VZSUQtMTU5MUQ0QjZFQUY5OEQwMTA0ODY0QjY5MDNBNDhERDAwMjYwNzdEMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAN3VCjjVBxjmREHAXozpqTk8eet-ELA8kLt3vjfq0RUNP84ZA6KZqi88zN1EplbJVdGU1IqCHksjBpcPkE6S8SfuLjYMTFxO98ggWCSUSf5dY_tPD2gbvGw1yQw6FwiN3f9ezRulX0iHFx7RDZSio1nG0W6OeSKXAn2NkTn_8KTT2-WrnyCu-Y2pRAtZTV4a0slUzDdL8AOtusJvDdcXktQXLgiIWowLYqv_QRrQCf3mrO-zs7cX9pRF67DkvFljG_79BfZ8W8xv7V1cWsDmFoEZJhBoSyURvgiG0EF6GWvSY1kMwOOPP6JhYh7xj4rhLgf4nuA4si2R6lx1yCWcJq5H6FJ4yNQ2gzhyS-a897T38fJJSHsSZIEWl-y3uwV0SU9rE_92g6VHoxRQfM8R9gAl_DbsfIqJouva4BV0vgkyK1A1QP60iPzV-N0vjy5-bTlTdE9P4M0jyskNcex-ndUvryXvUHhrqgn-dGszHXND-ul3D3-y9MFBxWOtyTwQaZeNkKur-IRXnaDtGNPr7fmnqbxEtLcUdl8nnzRdt1QRuJM4Q_cA2veq3abEAQzbk5HiRBt0tt7i4ua6egc5yIWaHbj0M9409Usi9vGmaCQB_4neZBRBCP5W6gjgK6U43W6Pwb8ugJO9rk_xlAi3BSjfxhaF8AHerzGRRd1rY_MpAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBR27Ef3V-wqXtQOHZgCXhTLKFHirTAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAAlWh9LMUF_jXJILn6eLq7Ci3NR_wmkWTL3xArP3QdDrM9f0f3FWbrW-vW_bPZ-bWnvwHGs5acGOF70Pfay0nFnIgN7v4Ap2QSz8ZV1tT3G_FV7XVQn8DLrFZS0P-kwaj-mqOGyy_i3avfeTodEbY2md4aCmMks6pgA9_0cn2d6OBbFhUwmFRdSXyTgfLosZQ4ZM6jZOTcVS_AXTMKachTenOUsu4rq-mY6MEnZUDMJRO8etq1txBjfkzU0z_OBAUv1JbOyv8B6DiPtny4_b9YcCBVZDzeTbiuEpihjMOd9wVbLnGPfjqdpri1LfpBeb2NqU8-3Xzx2vC3IhGSL-MSWbYeegkeKC-VWVIrEdUPo7CYjRYmxixx7njE2WmWF-njjz0Ym6jI-42HhC8co0ZO8ShDX_TWzUIAkuTO_8XsNEgRx0O4FvYMvcUD7HCPAWmymGeRFulV26ew1ZVe8TbTuAutzAYWiAW_3us8eMgsgK-8RrTdA_4LgMG8cMjAFPPSE4pWnnKtMau09Kd6Bwby_JUf4Jzj3334Yy5MgRU8ZdKpIR7ttVJf9nYgOvgG2gZxlK1WkylOYgQ_cy_P_wd4c8fKIsmlwcLubz190MBjqYRrzVDiRv-ZvzfKmYNkzfmS0148quLg8bOonBPyO-NxHpmBkLO1RxTKsH9ROEjXPSZ3B1YkFyZWFZATYAAQALAAYEcgAgnf_L82w4OuaZ-5ho3G3LidcVOIS-KAOSLBJBWL-tIq4AEAAQCAAAAAAAAQDzbbse88SEq3l9_bklBUIPY9_zMoQS3MY2uKDIP5xBwev-fclctYhzqcbLfFXEKn6_hzTNgwcBgnk0gFhipAXdeZMF6KqRA-EP8tf8ADrPJVO9MIJlW4XBbX34yDlaRMGHWJkhMabvcl9vKXs_zKO-1Sb9477yaBkB5UY8MUc9DQfMGU-V7FYYgiTcxEzZ73AV1a8NPoGBkPqydB_x4izEOiLzhQHzZn3pw7hF3FsmCFPAhN2JVvySJwNrJ6uwCimcHGnHEB3LudUOPxU8gVKJCGG6DGowwYg6Xv3nr2Bx4wVtUQw7OjGGTdCHuTgXgRZJ1ZDNnY1KvDIQ-8Hpt6AbaGNlcnRJbmZvWKH_VENHgBcAIgALI7E9zE4hRG5gi5X8ZLOx1nBs5TR7o6Xw71F13vGQZz0AFHp1OQIvOLQ4sj6kUd_LwZzGOaSwAAAADQbAUv_smt0ontxTmAHHtCFXIAKHEQAiAAs5vYGEPFPXdHYZ6Aq9NCq_CAKTnsob15P2IM2R8VLkaAAiAAuFGYRlTgi5CMlz2ZQpoPguuB4VKNKMCAeEeFVebh5JrmhhdXRoRGF0YVkBZ8Y-yg23lncBLbnB_IQLgUnhjmcR07HUho1A5EcRGCzCRQAAAAAImHBYytxLgbbhMN5Q3L6WACBc1Q_SupD21PWprh4LkrZmkeuGnespu_71rFtW8GMJxaQBAwM5AQAgWQEA8227HvPEhKt5ff25JQVCD2Pf8zKEEtzGNrigyD-cQcHr_n3JXLWIc6nGy3xVxCp-v4c0zYMHAYJ5NIBYYqQF3XmTBeiqkQPhD_LX_AA6zyVTvTCCZVuFwW19-Mg5WkTBh1iZITGm73Jfbyl7P8yjvtUm_eO-8mgZAeVGPDFHPQ0HzBlPlexWGIIk3MRM2e9wFdWvDT6BgZD6snQf8eIsxDoi84UB82Z96cO4RdxbJghTwITdiVb8kicDayersAopnBxpxxAdy7nVDj8VPIFSiQhhugxqMMGIOl79569gceMFbVEMOzoxhk3Qh7k4F4EWSdWQzZ2NSrwyEPvB6begGyFDAQAB'
tpm_credential_id = 'XNUP0rqQ9tT1qa4eC5K2ZpHrhp3rKbv-9axbVvBjCcU'
tpm_client_data = 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSERNTmFST3BURDZiRU1jZ1JuSFpidEpoOU8zZGdiNjJHRUlZTThsX2dOdyIsIm9yaWdpbiI6Imh0dHBzOi8vZGFzaGJvYXJkLmRldi5lZHVpZC5zZSIsImNyb3NzT3JpZ2luIjpmYWxzZX0'
print(AttestationObject(websafe_decode(tpm_attestation_object)))
tpm_att = Attestation.from_base64(tpm_attestation_object)
print(tpm_att)
tpm_verified = md.verify_attestation(attestation=tpm_att, client_data=websafe_decode(tpm_client_data))
print(f'tpm: {tpm_verified}')
