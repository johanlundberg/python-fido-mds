# -*- coding: utf-8 -*-
import logging
from pathlib import Path
from typing import Optional
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import (
    Version,
    NameOID,
    BasicConstraints,
    ObjectIdentifier,
    ExtensionNotFound,
    UnrecognizedExtension,
)
from fido2.utils import websafe_decode
from iso3166 import countries_by_alpha2

from fido_mds.helpers import get_cose_alg
from fido_mds.models.fido_mds import FidoMD

__author__ = 'lundberg'

from fido_mds.models.webauthn import Attestation, AttestationFormat

logger = logging.getLogger(__name__)


class ValidationError(ValueError):
    pass


class FidoMetadataStore:
    def __init__(self, metadata_path: Optional[Path] = None):
        # default to bundled metadata
        if metadata_path is None:
            metadata_path = Path('./data/metadata.json')
        try:
            with open(metadata_path, 'r') as f:
                self.metadata = FidoMD.parse_raw(f.read())
        except IOError as e:
            logger.error(f'Could not open file {f}: {e}')

    def verify_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        if attestation.fmt is AttestationFormat.PACKED:
            return self.verify_packed_attestation(attestation=attestation, client_data=client_data)
        raise NotImplementedError(f'verification of {attestation.fmt.value} not implemented')

    def verify_packed_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        # if there is a cert chain it is a FULL packed attestation
        if attestation.att_statement.x5c:
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
            client_data_hash = hashes.Hash(hashes.SHA256())
            client_data_hash.update(client_data)
            signature_base = attestation.raw_auth_data + client_data_hash.finalize()
            alg = get_cose_alg(attestation.att_statement.alg)

            try:
                leaf_cert.public_key().verify(
                    signature=attestation.att_statement.sig, signature_algorithm=alg.alg, data=signature_base,
                )
            except InvalidSignature:
                raise ValidationError('signature does not match data')
        return False


md = FidoMetadataStore()
# print(md.metadata.json())

# orange yubikey
yubikey_4 = 'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgUHqDeN8I0KSrvYbA5eQ_g_csqzOgY8Rfmwtnn_94i-ECIQCuKt86sg6jgTf0EVUlSqHjcLcLce5X65fF5jIDxx8pHGN4NWOBWQJIMIICRDCCAS6gAwIBAgIEVWK-oDALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE0MzI1MzQ2ODgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARLMx93PYFEuZlcvkWFUX4XWDqkdiNpXL6FrEgsgBnyyblGeuBFsOZvExsuoyQ8kf2mAuMY8_xdjSp6uucr0UMJozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNTATBgsrBgEEAYLlHAIBAQQEAwIFIDALBgkqhkiG9w0BAQsDggEBAKwW2bNutrOpt211lLNPWfT3PtvJ_espNetrRRyr9B0l0-cWFNdHJgTKcqV44yPtt2AEaF8F59G5vgXbbpRA-sXPyTKmyvroUpl3LtsCeCAgPNQUHT7rb2os6Z45V4AyY6urjW7EgKffCErSy6e31td8lMPrwLFm-WBXyvX-OmMeompDN2Kjb77PTPRFCWJf1a8QSap8i8dommZZ6a9d6PDXLCiCUXTFDgarf2oHkIN7bbMqv9y8qDXLuwkO8fDZnghpv-nlZ2TEIw5sBXcpsBDeDsX5zOTJHCgmIY6oCBq7lpFR7BZyWvKo2V53lbyqInqblEMgxCdhnKr4VNmCmNdoYXV0aERhdGFYxNz3BHEmKmoM4iTRAmMUgSjEdNSeKZskhyDzwzPuNmHTQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEBUxM3Zkcq64TUqrXr2nh7urP1cRiwmeX5tyGj22YmQTvRu5z8c-wrptwqJ6Gef15JjZGvkb6epX-6ANI7MNC57pQECAyYgASFYIChWSEnPLFGZFdeiujDUrDRE8YkL5sYM-i_mDgC2QtBPIlgg5vKsrM8Z7fI5rJAiZBVVftNMjiVIX56mKsf6eCZZgU0'
yubikey_4_client_data = 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicUUyQi1FQ25ZRHhuRXZlbzVIVmQ0ZjFxVUotNnhkbU9oNHFIenAtSnI2TSIsIm9yaWdpbiI6Imh0dHBzOi8vZGFzaGJvYXJkLmVkdWlkLmRvY2tlciIsImNyb3NzT3JpZ2luIjpmYWxzZX0'
yubikey_4_credential_id = 'VMTN2ZHKuuE1Kq169p4e7qz9XEYsJnl-bcho9tmJkE70buc_HPsK6bcKiehnn9eSY2Rr5G-nqV_ugDSOzDQuew'


yubikey_5_nfc_attestation_obj = 'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIRbB2kR7PfC27xsxNGePmQcKA_LIRaK0Q0HYX2kVPj5AiEAjL4P92FwUidaVAKfT_mSuH5v0maMshUMRtlxzJZ017RjeDVjgVkCwTCCAr0wggGloAMCAQICBB6PhzQwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDUxMjcyMjc0MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKh5-CM47RSUusBwS8x_xmPRsnFxWXYkMQHHYFEV18FSnigcHGcyLThLXNVd0-mBjV_YXCKvMm4MZPwgr-M_I2ajbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEC_AV5-BE0fqsRa7Wo25ICowDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAhpP_Yt8NV3nUdI1_yNECJzGKjlgOajpXwQjpTgPDhWizZolPzlYkvko-_X80EYs9mTdD95KhmJFgyPya4LBOPfnuFePojAT8gqjcv1gY4QjcwpaFd655_2YrlHNOPexFlzBdc-blXuK-uc2WeMoJNeUz62OPjib6u4F82kQfvpgxgyrl9uKtmS-eu9tMYiOLj416tIHW0yY7zb-eSldVA3CYitWBNED6AyyttnI8rdj417qAn3W0PP-gpbmt0UIy752eFIEmOCM8TKSoc7n4rJjjK6GRZ2BuFZCfzdtKLf-9rkYgJJ-aZkasgeSDLREZ_r-qcxqILaJad4J9RtGQF2hhdXRoRGF0YVjE3PcEcSYqagziJNECYxSBKMR01J4pmySHIPPDM-42YdNBAAAAAS_AV5-BE0fqsRa7Wo25ICoAQDjqf6lUSwig_VinV7E7AHW5-gRqhriPK_Z08Am10wQyl5n6uZ7yWrmNKMd3ASnTuQLZJBQ87gmnVg4N7AU6e1qlAQIDJiABIVggy6WcmMhq0lbHKQMCpHf8D2dczddOstIL5Uld0xzu5Z0iWCD5mY6aAZFwPV-KnwpPi7oiP22CGfqiOvLnLTt9RCCYuA'
yubikey_5_nfc_client_data = 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMlpLQ1NDMWRCOU1CbnBqWGZoLXhYNDBmM3dCXzFCLXM1U0hEMFlNU001QSIsIm9yaWdpbiI6Imh0dHBzOi8vZGFzaGJvYXJkLmVkdWlkLmRvY2tlciIsImNyb3NzT3JpZ2luIjpmYWxzZX0'
print(websafe_decode(yubikey_5_nfc_client_data))
yubikey_5_nfc_credential_id = 'OOp_qVRLCKD9WKdXsTsAdbn6BGqGuI8r9nTwCbXTBDKXmfq5nvJauY0ox3cBKdO5AtkkFDzuCadWDg3sBTp7Wg'
yubikey_5_nfc_att = Attestation.from_base64(yubikey_5_nfc_attestation_obj)
print(yubikey_5_nfc_att)
print()
yubico_security_key = 'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAOy8_rzA7xpWVGMoc_0JeB-lqCY_sFygaeajB0fG8XpzAiBsb5ZSbuivkHIkh0RaPs2S_xMZyqg7a_Y9uqmnDrOzcGN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjE3PcEcSYqagziJNECYxSBKMR01J4pmySHIPPDM-42YdNBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQG_jkwdob5C0DyOrfU5xbbdwa3o-9YXYv-m7RkoSuQwEBYNA4HWgPc64doYQPfpH51hKviKieGyKyudKgoOx0tWlAQIDJiABIVggJqHVYvUJM0ZuzlrZ3X98czBnZIKXf-6ijfFGDKqLACEiWCBPAxtczXxLIGHjjiag21Skr16YH8ajF9n7QwcNXhyx0A'
yubico_security_key_att = Attestation.from_base64(yubico_security_key)
print(yubico_security_key_att)

print(md.verify_attestation(attestation=yubikey_5_nfc_att, client_data=websafe_decode(yubikey_5_nfc_client_data)))
