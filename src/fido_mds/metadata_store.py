# -*- coding: utf-8 -*-
import logging
from importlib import resources
from pathlib import Path
from typing import Dict, List, Optional, Union
from uuid import UUID

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import Certificate
from fido2.attestation import (
    AndroidSafetynetAttestation,
    AppleAttestation,
    FidoU2FAttestation,
    PackedAttestation,
    TpmAttestation,
)
from fido2.attestation.base import InvalidAttestation
from fido2.cose import CoseKey

from fido_mds.exceptions import AttestationVerificationError, MetadataValidationError
from fido_mds.helpers import cert_chain_verified, hash_with, load_raw_cert
from fido_mds.models.fido_mds import Entry, FidoMD

__author__ = 'lundberg'

from fido_mds.models.webauthn import Attestation, AttestationFormat

logger = logging.getLogger(__name__)


class FidoMetadataStore:
    def __init__(self, metadata_path: Optional[Path] = None):
        # default to bundled metadata
        if metadata_path is not None:
            try:
                with open(metadata_path, 'r') as mdf:
                    self.metadata = FidoMD.parse_raw(mdf.read())
            except IOError as e:
                logger.error(f'Could not open file {mdf}: {e}')
        else:
            with resources.open_text('fido_mds.data', 'metadata.json') as f:
                self.metadata = FidoMD.parse_raw(f.read())

        self.external_root_certs: Dict[str, List[Certificate]] = {}
        # load known external root certs
        with resources.open_binary('fido_mds.data', 'apple_webauthn_root_ca.pem') as arc:
            self.add_external_root_certs(name='apple', root_certs=[arc.read()])
        self._entry_cache: Dict[Union[str, UUID], Entry] = {}

    def add_external_root_certs(self, name: str, root_certs: List[Union[bytes, str]]) -> None:
        certs = []
        for cert in root_certs:
            certs.append(load_raw_cert(cert=cert))
        self.external_root_certs[name] = certs

    def get_entry_for_aaguid(self, aaguid: UUID) -> Optional[Entry]:
        if aaguid in self._entry_cache:
            return self._entry_cache[aaguid]

        for entry in self.metadata.entries:
            if entry.aaguid is not None and UUID(entry.aaguid) == aaguid:
                self._entry_cache[aaguid] = entry
                return entry
        return None

    def get_entry_for_certificate_key_identifier(self, cki: str) -> Optional[Entry]:
        if cki in self._entry_cache:
            return self._entry_cache[cki]

        for entry in self.metadata.entries:
            if (
                entry.attestation_certificate_key_identifiers is not None
                and cki in entry.attestation_certificate_key_identifiers
            ):
                self._entry_cache[cki] = entry
                return entry
        return None

    def get_entry(self, aaguid: Optional[UUID] = None, cki: Optional[str] = None) -> Optional[Entry]:
        if aaguid:
            return self.get_entry_for_aaguid(aaguid=aaguid)
        elif cki:
            return self.get_entry_for_certificate_key_identifier(cki=cki)
        return None

    def get_root_certs(self, aaguid: Optional[UUID] = None, cki: Optional[str] = None) -> List[Certificate]:
        metadata_entry = self.get_entry(aaguid=aaguid, cki=cki)
        if metadata_entry:
            return [
                load_raw_cert(cert=root_cert)
                for root_cert in metadata_entry.metadata_statement.attestation_root_certificates
            ]
        return list()

    def get_authentication_algs(self, aaguid: Optional[UUID] = None, cki: Optional[str] = None) -> List[str]:
        metadata_entry = self.get_entry(aaguid=aaguid, cki=cki)
        if metadata_entry:
            return metadata_entry.metadata_statement.authentication_algorithms
        return list()

    def verify_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        if attestation.fmt is AttestationFormat.PACKED:
            return self.verify_packed_attestation(attestation=attestation, client_data=client_data)
        if attestation.fmt is AttestationFormat.APPLE:
            return self.verify_apple_anonymous_attestation(attestation=attestation, client_data=client_data)
        if attestation.fmt is AttestationFormat.TPM:
            return self.verify_tpm_attestation(attestation=attestation, client_data=client_data)
        if attestation.fmt is AttestationFormat.ANDROID_SAFETYNET:
            return self.verify_android_safetynet_attestation(attestation=attestation, client_data=client_data)
        if attestation.fmt is AttestationFormat.FIDO_U2F:
            return self.verify_fido_u2f_attestation(attestation=attestation, client_data=client_data)
        raise NotImplementedError(f'verification of {attestation.fmt.value} not implemented')

    def verify_packed_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        cose_key = CoseKey.for_alg(attestation.att_statement.alg)
        client_data_hash = hash_with(hash_alg=cose_key._HASH_ALG, data=client_data)
        try:
            PackedAttestation().verify(
                statement=attestation.attestation_obj.att_statement,
                auth_data=attestation.attestation_obj.auth_data,
                client_data_hash=client_data_hash,
            )
        except InvalidAttestation as e:
            raise AttestationVerificationError(f'Invalid attestation: {e}')

        # validate leaf cert again root cert in metadata
        root_certs = self.get_root_certs(aaguid=attestation.auth_data.credential_data.aaguid)
        if cert_chain_verified(cert_chain=attestation.att_statement.x5c, root_certs=root_certs):
            return True
        raise MetadataValidationError('metadata root cert does not match attestation cert')

    def verify_apple_anonymous_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        client_data_hash = hash_with(hash_alg=SHA256(), data=client_data)
        try:
            AppleAttestation().verify(
                statement=attestation.attestation_obj.att_statement,
                auth_data=attestation.attestation_obj.auth_data,
                client_data_hash=client_data_hash,
            )
        except InvalidAttestation as e:
            raise AttestationVerificationError(f'Invalid attestation: {e}')

        # validata leaf cert against Apple root cert
        if cert_chain_verified(cert_chain=attestation.att_statement.x5c, root_certs=self.external_root_certs['apple']):
            return True
        raise MetadataValidationError('metadata root cert does not match attestation cert')

    def verify_tpm_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        client_data_hash = hash_with(hash_alg=SHA256(), data=client_data)
        try:
            TpmAttestation().verify(
                statement=attestation.attestation_obj.att_statement,
                auth_data=attestation.attestation_obj.auth_data,
                client_data_hash=client_data_hash,
            )
        except InvalidAttestation as e:
            raise AttestationVerificationError(f'Invalid attestation: {e}')

        # validata leaf cert again root cert in metadata
        root_certs = self.get_root_certs(aaguid=attestation.auth_data.credential_data.aaguid)
        if cert_chain_verified(cert_chain=attestation.att_statement.x5c, root_certs=root_certs):
            return True
        raise MetadataValidationError('metadata root cert does not match attestation cert')

    def verify_android_safetynet_attestation(
        self, attestation: Attestation, client_data: bytes, allow_rooted_device: bool = False
    ) -> bool:
        client_data_hash = hash_with(hash_alg=SHA256(), data=client_data)
        try:
            AndroidSafetynetAttestation(allow_rooted=allow_rooted_device).verify(
                statement=attestation.attestation_obj.att_statement,
                auth_data=attestation.attestation_obj.auth_data,
                client_data_hash=client_data_hash,
            )
        except InvalidAttestation as e:
            raise AttestationVerificationError(f'Invalid attestation: {e}')

        # TODO: jwt header alg should correspond to a authentication alg in metadata, but how?
        #   ex. header alg RS256 is not in metadata algs ['secp256r1_ecdsa_sha256_raw']
        # authn_algs = self.get_authentication_algs(aaguid=attestation.auth_data.credential_data.aaguid)
        # alg = attestation.att_statement.response.header.alg
        # validata leaf cert again root cert in metadata
        if not attestation.att_statement.response:
            raise AttestationVerificationError('attestation is missing response jwt')
        root_certs = self.get_root_certs(aaguid=attestation.auth_data.credential_data.aaguid)
        if cert_chain_verified(cert_chain=attestation.att_statement.response.header.x5c, root_certs=root_certs):
            return True
        raise MetadataValidationError('metadata root cert does not match attestation cert')

    def verify_fido_u2f_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        client_data_hash = hash_with(hash_alg=SHA256(), data=client_data)
        try:
            FidoU2FAttestation().verify(
                statement=attestation.attestation_obj.att_statement,
                auth_data=attestation.attestation_obj.auth_data,
                client_data_hash=client_data_hash,
            )
        except InvalidAttestation as e:
            raise AttestationVerificationError(f'Invalid attestation: {e}')

        root_certs = self.get_root_certs(cki=attestation.certificate_key_identifier)
        if cert_chain_verified(cert_chain=attestation.att_statement.x5c, root_certs=root_certs):
            return True
        raise MetadataValidationError('metadata root cert does not match attestation cert')
