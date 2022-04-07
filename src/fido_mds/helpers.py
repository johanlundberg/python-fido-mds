# -*- coding: utf-8 -*-

import logging

from dataclasses import dataclass
from typing import Union, List, Type

from OpenSSL import crypto
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurveSignatureAlgorithm, EllipticCurvePublicKey

from cryptography.hazmat.primitives.asymmetric.types import CERTIFICATE_PUBLIC_KEY_TYPES

from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm

__author__ = 'lundberg'

from cryptography.x509 import Certificate

logger = logging.getLogger(__name__)

COSE_ALGS = {
    '-65535': 'RS1',
    '-260': 'WalnutDSA',
    '-259': 'RS512',
    '-258': 'RS384',
    '-257': 'RS256',
    '-47': 'ES256K',
    '-46': 'HSS-LMS',
    '-45': 'SHAKE256',
    '-44': 'SHA-512',
    '-43': 'SHA-384',
    '-42': 'RSAES-OAEP w/ SHA-512',
    '-41': 'RSAES-OAEP w/ SHA-256',
    '-40': 'RSAES-OAEP w/ RFC 8017 default parameters',
    '-39': 'PS512',
    '-38': 'PS384',
    '-37': 'PS256',
    '-36': 'ES512',
    '-35': 'ES384',
    '-34': 'ECDH-SS + A256KW',
    '-33': 'ECDH-SS + A192KW',
    '-32': 'ECDH-SS + A128KW',
    '-31': 'ECDH-ES + A256KW',
    '-30': 'ECDH-ES + A192KW',
    '-29': 'ECDH-ES + A128KW',
    '-28': 'ECDH-SS + HKDF-512',
    '-27': 'ECDH-SS + HKDF-256',
    '-26': 'ECDH-ES + HKDF-512',
    '-25': 'ECDH-ES + HKDF-256',
    '-18': 'SHAKE128',
    '-17': 'SHA-512/256',
    '-16': 'SHA-256',
    '-15': 'SHA-256/64',
    '-14': 'SHA-1',
    '-13': 'direct+HKDF-AES-256',
    '-12': 'direct+HKDF-AES-128',
    '-11': 'direct+HKDF-SHA-512',
    '-10': 'direct+HKDF-SHA-256',
    '-8': 'EdDSA',
    '-7': 'ES256',
    '-6': 'direct',
    '-5': 'A256KW',
    '-4': 'A192KW',
    '-3': 'A128KW',
    '0': 'Reserved',
    '1': 'A128GCM',
    '2': 'A192GCM',
    '3': 'A256GCM',
    '4': 'HMAC 256/64',
    '5': 'HMAC 256/256',
    '6': 'HMAC 384/384',
    '7': 'HMAC 512/512',
    '10': 'AES-CCM-16-64-128',
    '11': 'AES-CCM-16-64-256',
    '12': 'AES-CCM-64-64-128',
    '13': 'AES-CCM-64-64-256',
    '14': 'AES-MAC 128/64',
    '15': 'AES-MAC 256/64',
    '24': 'ChaCha20/Poly1305',
    '25': 'AES-MAC 128/128',
    '26': 'AES-MAC 256/128',
    '30': 'AES-CCM-16-128-128',
    '31': 'AES-CCM-16-128-256',
    '32': 'AES-CCM-64-128-128',
    '33': 'AES-CCM-64-128-256',
    '34': 'IV-GENERATION',
}


@dataclass
class CoseAlg:
    hash_alg: HashAlgorithm
    sig_alg: EllipticCurveSignatureAlgorithm

    def hash(self, data: bytes) -> bytes:
        h = hashes.Hash(self.hash_alg)
        h.update(data)
        return h.finalize()

    def verify(self, key: CERTIFICATE_PUBLIC_KEY_TYPES, signature: bytes, data: bytes) -> bool:
        try:
            key.verify(
                signature=signature,
                signature_algorithm=self.sig_alg,
                data=data,
            )
            return True
        except InvalidSignature as e:
            logger.debug(f'Signature verification failed: {e}')
        return False


def get_cose_alg(alg: int) -> CoseAlg:
    alg_name = COSE_ALGS.get(str(alg))
    if alg_name == 'ES256':
        return CoseAlg(hash_alg=SHA256(), sig_alg=ECDSA(algorithm=SHA256()))
    if alg_name == 'RS256':
        pass
    raise NotImplementedError(f'{alg_name} not implemented')


def load_raw_cert(cert: Union[bytes, str]) -> x509.Certificate:
    if isinstance(cert, bytes):
        cert = cert.decode()
    if cert.startswith('-----BEGIN CERTIFICATE-----'):
        return x509.load_pem_x509_certificate(bytes(cert, encoding='utf-8'))
    raw_cert = f'-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----'
    return x509.load_pem_x509_certificate(bytes(raw_cert, encoding='utf-8'))


def cert_chain_verified(cert_chain: List[Certificate], root_certs: List[Certificate]) -> bool:
    cert_verified = False
    cert_to_check = cert_chain[0]  # first cert in chain is the one we want to verify
    # create store and add root cert
    for root_cert in root_certs:
        store = crypto.X509Store()
        store.add_cert(crypto.X509.from_cryptography(root_cert))

        # add the rest of the chain to the store
        for chain_cert in cert_chain[1:]:
            cert = crypto.X509.from_cryptography(chain_cert)
            store.add_cert(cert)

        ctx = crypto.X509StoreContext(store, crypto.X509.from_cryptography(cert_to_check))
        try:
            ctx.verify_certificate()
            cert_verified = True
            logger.debug(f'Root cert with SHA256 fingerprint {root_cert.fingerprint(SHA256())} matched')
        except crypto.X509StoreContextError:
            logger.debug(f'Root cert with SHA256 fingerprint {root_cert.fingerprint(SHA256())} did NOT match')
            continue
    return cert_verified
