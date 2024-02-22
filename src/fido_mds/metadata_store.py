# -*- coding: utf-8 -*-
import logging
from importlib import resources
from pathlib import Path
from typing import Dict, List, Optional, Type, TypeVar, Union
from uuid import UUID

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import Certificate
from fido2.attestation import AndroidSafetynetAttestation, AppleAttestation
from fido2.attestation import Attestation as Fido2Attestation
from fido2.attestation import FidoU2FAttestation, PackedAttestation, TpmAttestation
from fido2.attestation.base import InvalidAttestation
from fido2.cose import CoseKey

from fido_mds.exceptions import AttestationVerificationError, MetadataValidationError
from fido_mds.helpers import cert_chain_verified, hash_with, load_raw_cert
from fido_mds.models.fido_mds import Entry, FidoMD
from fido_mds.models.webauthn import Attestation, AttestationFormat

__author__ = "lundberg"


TFido2AttestationSubclass = TypeVar("TFido2AttestationSubclass", bound=Fido2Attestation)

logger = logging.getLogger(__name__)

ERROR_MSG_CERT_DOES_NOT_MATCH = "metadata root cert does not match attestation cert"


class FidoMetadataStore:
    def __init__(self, metadata_path: Optional[Path] = None):
        # default to bundled metadata
        if metadata_path is not None:
            try:
                with open(metadata_path, "r") as mdf:
                    self.metadata = FidoMD.model_validate_json(mdf.read())
            except IOError as e:
                logger.error(f"Could not open file {mdf}: {e}")
        else:
            with resources.open_text("fido_mds.data", "metadata.json") as f:
                self.metadata = FidoMD.model_validate_json(f.read())

        self._entry_cache: Dict[Union[str, UUID], Entry] = {}
        self._other_cache: Dict[str, List[Union[str, int]]] = {}
        self.external_root_certs: Dict[str, List[Certificate]] = {}

        # load known external root certs
        with resources.open_binary("fido_mds.data", "apple_webauthn_root_ca.pem") as arc:
            self.add_external_root_certs(name="apple", root_certs=[arc.read()])

    @staticmethod
    def _verify_attestation_as_type(
        attestation_type: Type[TFido2AttestationSubclass],
        attestation: Attestation,
        client_data_hash: bytes,
        allow_rooted_device: bool = False,
    ):
        if attestation_type is AndroidSafetynetAttestation:
            # AndroidSafetynetAttestation do expect argument allow_rooted
            fido2_attestation = attestation_type(allow_rooted=allow_rooted_device)  # type: ignore[call-arg]
        else:
            fido2_attestation = attestation_type()
        try:
            fido2_attestation.verify(
                statement=attestation.attestation_obj.att_stmt,
                auth_data=attestation.attestation_obj.auth_data,
                client_data_hash=client_data_hash,
            )
        except InvalidAttestation as e:
            raise AttestationVerificationError(f"Invalid attestation: {e}")

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

    def get_entry(self, authenticator_id: Union[UUID, str]) -> Optional[Entry]:
        if isinstance(authenticator_id, UUID):
            return self.get_entry_for_aaguid(aaguid=authenticator_id)
        else:
            return self.get_entry_for_certificate_key_identifier(cki=authenticator_id)

    def get_root_certs(self, authenticator_id: Union[UUID, str]) -> List[Certificate]:
        metadata_entry = self.get_entry(authenticator_id=authenticator_id)
        if metadata_entry:
            return [
                load_raw_cert(cert=root_cert)
                for root_cert in metadata_entry.metadata_statement.attestation_root_certificates
            ]
        return list()

    def get_authentication_algs(self, authenticator_id: Union[UUID, str]) -> List[str]:
        metadata_entry = self.get_entry(authenticator_id=authenticator_id)
        if metadata_entry:
            return metadata_entry.metadata_statement.authentication_algorithms
        return list()

    def get_user_verification_methods(self) -> List[Union[str, int]]:
        key = "user_verification_methods"
        if key in self._other_cache:
            return self._other_cache[key]
        res = set()
        for entry in self.metadata.entries:
            for uvd in entry.metadata_statement.get_user_verification_details():
                res.add(uvd.user_verification_method)
        self._other_cache[key] = list(res)
        return list(res)

    def get_key_protections(self) -> List[Union[str, int]]:
        key = "key_protections"
        if key in self._other_cache:
            return self._other_cache[key]
        res = set()
        for entry in self.metadata.entries:
            for item in entry.metadata_statement.key_protection:
                res.add(item)
        self._other_cache[key] = list(res)
        return list(res)

    def get_crypto_strengths(self) -> List[Union[str, int]]:
        key = "crypto_strengths"
        if key in self._other_cache:
            return self._other_cache[key]
        res = set()
        for entry in self.metadata.entries:
            if entry.metadata_statement.crypto_strength is not None:
                res.add(entry.metadata_statement.crypto_strength)
        self._other_cache[key] = list(res)
        return list(res)

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
        raise NotImplementedError(f"verification of {attestation.fmt.value} not implemented")

    def verify_packed_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        if attestation.att_statement.alg is None:
            raise AttestationVerificationError("Algorithm missing in attestation statement for packed attestation")
        cose_key = CoseKey.for_alg(attestation.att_statement.alg)
        # type ignore as subclasses do have _HASH_ALG implemented
        client_data_hash = hash_with(hash_alg=cose_key._HASH_ALG, data=client_data)  # type: ignore[attr-defined]
        self._verify_attestation_as_type(PackedAttestation, attestation=attestation, client_data_hash=client_data_hash)

        # validate leaf cert against root cert in metadata
        root_certs = self.get_root_certs(authenticator_id=attestation.auth_data.credential_data.aaguid)
        if cert_chain_verified(cert_chain=attestation.att_statement.x5c, root_certs=root_certs):
            return True
        raise MetadataValidationError(ERROR_MSG_CERT_DOES_NOT_MATCH)

    def verify_apple_anonymous_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        client_data_hash = hash_with(hash_alg=SHA256(), data=client_data)
        self._verify_attestation_as_type(AppleAttestation, attestation=attestation, client_data_hash=client_data_hash)

        # validata leaf cert against Apple root cert
        if cert_chain_verified(cert_chain=attestation.att_statement.x5c, root_certs=self.external_root_certs["apple"]):
            return True
        raise MetadataValidationError(ERROR_MSG_CERT_DOES_NOT_MATCH)

    def verify_tpm_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        client_data_hash = hash_with(hash_alg=SHA256(), data=client_data)
        self._verify_attestation_as_type(TpmAttestation, attestation=attestation, client_data_hash=client_data_hash)

        # validata leaf cert against root cert in metadata
        root_certs = self.get_root_certs(authenticator_id=attestation.auth_data.credential_data.aaguid)
        if cert_chain_verified(cert_chain=attestation.att_statement.x5c, root_certs=root_certs):
            return True
        raise MetadataValidationError(ERROR_MSG_CERT_DOES_NOT_MATCH)

    def verify_android_safetynet_attestation(
        self, attestation: Attestation, client_data: bytes, allow_rooted_device: bool = False
    ) -> bool:
        client_data_hash = hash_with(hash_alg=SHA256(), data=client_data)
        self._verify_attestation_as_type(
            AndroidSafetynetAttestation,
            attestation=attestation,
            client_data_hash=client_data_hash,
            allow_rooted_device=allow_rooted_device,
        )

        # TODO: jwt header alg should correspond to a authentication alg in metadata, but how?
        #   ex. header alg RS256 is not in metadata algs ['secp256r1_ecdsa_sha256_raw']
        # authn_algs = self.get_authentication_algs(aaguid=attestation.auth_data.credential_data.aaguid)
        # alg = attestation.att_statement.response.header.alg
        # validata leaf cert against root cert in metadata
        if not attestation.att_statement.response:
            raise AttestationVerificationError("attestation is missing response jwt")
        root_certs = self.get_root_certs(authenticator_id=attestation.auth_data.credential_data.aaguid)
        if cert_chain_verified(cert_chain=attestation.att_statement.response.header.x5c, root_certs=root_certs):
            return True
        raise MetadataValidationError(ERROR_MSG_CERT_DOES_NOT_MATCH)

    def verify_fido_u2f_attestation(self, attestation: Attestation, client_data: bytes) -> bool:
        client_data_hash = hash_with(hash_alg=SHA256(), data=client_data)
        self._verify_attestation_as_type(FidoU2FAttestation, attestation=attestation, client_data_hash=client_data_hash)

        assert attestation.certificate_key_identifier is not None  # please mypy
        root_certs = self.get_root_certs(authenticator_id=attestation.certificate_key_identifier)
        if cert_chain_verified(cert_chain=attestation.att_statement.x5c, root_certs=root_certs):
            return True
        raise MetadataValidationError(ERROR_MSG_CERT_DOES_NOT_MATCH)
