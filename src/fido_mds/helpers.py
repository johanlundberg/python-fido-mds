# -*- coding: utf-8 -*-

import logging
from typing import List, Union

from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.x509 import Certificate

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


def hash_with(hash_alg: HashAlgorithm, data: bytes) -> bytes:
    h = hashes.Hash(hash_alg)
    h.update(data)
    return h.finalize()


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
            logger.debug(f'Root cert with SHA256 fingerprint {repr(root_cert.fingerprint(SHA256()))} matched')
            return True
        except crypto.X509StoreContextError:
            logger.debug(f'Root cert with SHA256 fingerprint {repr(root_cert.fingerprint(SHA256()))} did NOT match')
            continue
    return cert_verified
