# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, List, Mapping, Optional, Union
from uuid import UUID

from cryptography import x509
from cryptography.x509 import Certificate
from fido2.cose import ES256, PS256, RS1, RS256, CoseKey, EdDSA
from fido2.utils import websafe_decode
from fido2.webauthn import AttestationObject
from pydantic import BaseModel, ConfigDict, Field, field_validator

__author__ = "lundberg"

from fido_mds.helpers import load_raw_cert


class AttestationFormat(str, Enum):
    PACKED = "packed"
    FIDO_U2F = "fido-u2f"
    NONE = "none"
    ANDROID_KEY = "android-key"
    ANDROID_SAFETYNET = "android-safetynet"
    TPM = "tpm"
    APPLE = "apple"


class AttestationConfig(BaseModel):
    model_config = ConfigDict(from_attributes=True, arbitrary_types_allowed=True)


class AttestationStatementResponseHeader(AttestationConfig):
    alg: str
    x5c: List[Certificate] = Field(default=[])

    @field_validator("x5c", mode="before")
    def validate_x5c(cls, v: List[str]) -> List[Certificate]:
        return [load_raw_cert(item) for item in v]


class AttestationStatementResponsePayload(AttestationConfig):
    nonce: str
    timestampMs: datetime
    apk_package_name: str = Field(alias="apkPackageName")
    apk_digest_sha256: str = Field(alias="apkDigestSha256")
    cts_profile_match: bool = Field(alias="ctsProfileMatch")
    apk_certificate_digest_sha256: List[str] = Field(alias="apkCertificateDigestSha256")
    basic_integrity: bool = Field(alias="basicIntegrity")


class AttestationStatementResponse(AttestationConfig):
    header: AttestationStatementResponseHeader
    payload: AttestationStatementResponsePayload
    signature: str


class AttestationStatement(AttestationConfig):
    alg: Optional[int] = None
    sig: Optional[bytes] = None
    x5c: List[Certificate] = Field(default=[])
    ver: Optional[str] = None
    response: Optional[AttestationStatementResponse] = None
    cert_info: Optional[bytes] = Field(alias="certInfo", default=None)
    pub_area: Optional[bytes] = Field(alias="pubArea", default=None)

    @field_validator("x5c", mode="before")
    def validate_x5c(cls, v: List[bytes]) -> List[Certificate]:
        return [x509.load_der_x509_certificate(item) for item in v]

    @field_validator("response", mode="before")
    def validate_response(cls, v: bytes) -> Optional[AttestationStatementResponse]:
        header, payload, signature = v.decode(encoding="utf-8").split(".")
        return AttestationStatementResponse(
            header=AttestationStatementResponseHeader.parse_raw(websafe_decode(header)),
            payload=AttestationStatementResponsePayload.parse_raw(websafe_decode(payload)),
            signature=signature,
        )


class AuthenticatorFlags(AttestationConfig):
    attested: bool
    user_present: bool
    user_verified: bool
    extension_data: bool


class CredentialData(AttestationConfig):
    aaguid: UUID
    credential_id: bytes
    public_key: Union[ES256, RS256, PS256, EdDSA, RS1]

    @field_validator("aaguid", mode="before")
    def validate_aaguid(cls, v: bytes) -> UUID:
        return UUID(bytes=v)

    @field_validator("public_key", mode="before")
    def validate_public_key(cls, v: Mapping[int, Any]) -> CoseKey:
        return CoseKey.parse(v)


class AuthenticatorData(AttestationConfig):
    rp_id_hash: bytes
    flags: AuthenticatorFlags
    counter: int
    credential_data: CredentialData

    @field_validator("flags", mode="before")
    def validate_flags(cls, v: int) -> AuthenticatorFlags:
        # see https://www.w3.org/TR/webauthn/#table-authData
        user_present = bool(v & 0x01)
        user_verified = bool(v & 0x04)
        attested = bool(v & 0x40)
        extension_data = bool(v & 0x80)
        return AuthenticatorFlags(
            attested=attested,
            user_present=user_present,
            user_verified=user_verified,
            extension_data=extension_data,
        )


class Attestation(AttestationConfig):
    fmt: AttestationFormat
    att_statement: AttestationStatement
    auth_data: AuthenticatorData
    raw_attestation_obj: bytes

    @property
    def aaguid(self) -> Optional[UUID]:
        if self.fmt is not AttestationFormat.FIDO_U2F:
            return self.auth_data.credential_data.aaguid
        return None

    @property
    def certificate_key_identifier(self) -> Optional[str]:
        if self.fmt is AttestationFormat.FIDO_U2F and self.att_statement.x5c:
            cki = x509.SubjectKeyIdentifier.from_public_key(self.att_statement.x5c[0].public_key())
            return cki.digest.hex()
        return None

    @property
    def attestation_obj(self) -> AttestationObject:
        return AttestationObject(self.raw_attestation_obj)

    @classmethod
    def from_attestation_object(cls, data: AttestationObject) -> Attestation:
        d = {
            "fmt": data.fmt,
            "att_statement": data.att_stmt,
            "auth_data": data.auth_data,
            "raw_attestation_obj": bytes(data),
        }
        return cls.model_validate(d)

    @classmethod
    def from_base64(cls, data: str) -> Attestation:
        try:
            return cls.from_attestation_object(AttestationObject(websafe_decode(data)))
        except AttributeError as e:
            raise AttributeError(f"Could not parse attestation: {e}")
