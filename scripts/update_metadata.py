# -*- coding: utf-8 -*-
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List

from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from jwcrypto import jwk, jws


__author__ = 'lundberg'

METADATA = Path('./fido_alliance_mds.jwt')
ROOT_CERT = Path('./globalsign_root_r3.der')
CN = 'mds.fidoalliance.org'



def load_root_cert(path: Path) -> x509.Certificate:
    try:
        with open(path, 'rb') as f:
            return x509.load_der_x509_certificate(f.read())
    except IOError as e:
        print(f'Could not open {path}: {e}')
        sys.exit(1)


def load_cert_from_str(cert: str) -> x509.Certificate:
    raw_cert = f'-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----'
    return x509.load_pem_x509_certificate(raw_cert.encode())


def get_valid_cert(cert_chain: List[str], cn: str, root_cert: x509.Certificate) -> Optional[x509.Certificate]:
    if not cert_chain:
        return None

    cert_to_check = load_cert_from_str(cert_chain[0])  # first cert is the one used to sign the jwt

    # create store and add root cert
    store = crypto.X509Store()
    store.add_cert(crypto.X509.from_cryptography(root_cert))

    # add the rest of the chain to the store
    for chain_cert in cert_chain[1:]:
        cert = crypto.X509.from_cryptography(load_cert_from_str(chain_cert))
        store.add_cert(cert)

    ctx = crypto.X509StoreContext(store, crypto.X509.from_cryptography(cert_to_check))
    try:
        ctx.verify_certificate()
    except crypto.X509StoreContextError:
        return None

    # check if the Common Name matches the verified certificate
    if cert_to_check.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == cn:
        return cert_to_check

    return None


def load_jwk_from_x5c(x5c: List[str], root_cert: x509.Certificate) -> Optional[jwk.JWK]:
    valid_cert = get_valid_cert(cert_chain=x5c, cn=CN, root_cert=root_cert)
    if not valid_cert:
        return None
    try:
        _jwk = jwk.JWK.from_pyca(valid_cert.public_key())
        return _jwk
    except ValueError as e:
        print(f'Could not load JWK from certificate chain: {e}')

    return None


def load_metadata(path: Path, root_cert: x509.Certificate) -> Optional[Dict[str, Any]]:
    _jws = jws.JWS()
    try:
        with open(path, 'r') as f:
            # deserialize jws
            _jws.deserialize(raw_jws=f.read())
    except IOError as e:
        print(f'Could not open {path}: {e}')
    except (jws.InvalidJWSObject, IndexError):
        print(f'metadata could not be deserialized')
        return None

    # load JOSE headers
    headers = []
    if isinstance(_jws.jose_header, list):
        for item in _jws.jose_header:
            headers.append(item)
    elif isinstance(_jws.jose_header, dict):
        headers.append(_jws.jose_header)

    # verify jws
    verified = False
    for header in headers:
        cert_chain = header.get('x5c', [])
        try:
            _jwk = load_jwk_from_x5c(x5c=cert_chain, root_cert=root_cert)
            _jws.verify(key=_jwk)
            verified = True
            break
        except jws.InvalidJWSSignature:
            continue

    if verified:
        return json.loads(_jws.payload.decode())

    return None


def get_metadata(metadata_path: Path, root_cert_path: Path) -> Dict[str, Any]:
    root_cert = load_root_cert(path=root_cert_path)
    metadata = load_metadata(path=metadata_path, root_cert=root_cert)
    return metadata


if __name__ == '__main__':
    print(json.dumps(get_metadata(metadata_path=METADATA, root_cert_path=ROOT_CERT), indent=4))
