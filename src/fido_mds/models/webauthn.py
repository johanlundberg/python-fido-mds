# -*- coding: utf-8 -*-
from __future__ import annotations

from enum import Enum
from typing import List, TypeVar, Optional, Any
from uuid import UUID

from cryptography import x509
from cryptography.x509 import Certificate
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.ctap2 import AttestationObject
from fido2.utils import websafe_decode
from pydantic import BaseModel, Field, validator, root_validator

__author__ = 'lundberg'


class AttestationFormat(str, Enum):
    PACKED = 'packed'
    FIDO_U2F = 'fido-u2f'
    NONE = 'none'
    ANDROID_KEY = 'android-key'
    ANDROID_SAFTYNET = 'android-safetynet'
    TPM = 'tpm'
    APPLE = 'apple'


class AttestationConfig(BaseModel):
    class Config:
        orm_mode = True
        arbitrary_types_allowed = True


class AttestationStatement(AttestationConfig):
    alg: Optional[int]
    sig: bytes
    x5c: List[Certificate]

    @validator('x5c', pre=True)
    def validate_x5c(cls, v: List[bytes]) -> List[Certificate]:
        return [x509.load_der_x509_certificate(item) for item in v]


class CredentialData(AttestationConfig):
    aaguid: UUID
    credential_id: bytes
    public_key: CoseKey

    @validator('aaguid', pre=True)
    def validate_aaguid(cls, v: bytes) -> UUID:
        return UUID(bytes=v)


class AuthenticatorData(AttestationConfig):
    rp_id_hash: bytes
    flags: bytes
    counter: int
    credential_data: CredentialData


class Attestation(AttestationConfig):
    fmt: AttestationFormat
    att_statement: AttestationStatement
    auth_data: AuthenticatorData
    raw_auth_data: Optional[bytes]
    ep_att: Optional[Any]
    large_blob_key: Optional[Any]

    @classmethod
    def from_attestation_object(cls, data: AttestationObject) -> Attestation:
        obj = cls.from_orm(data)
        obj.raw_auth_data = data.auth_data
        return obj

    @classmethod
    def from_base64(cls, data: str) -> Attestation:
        return cls.from_attestation_object(AttestationObject(websafe_decode(data)))
