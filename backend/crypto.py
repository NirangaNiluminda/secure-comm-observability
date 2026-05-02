from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def generate_ec_keypair(curve=ec.SECP256R1()):
    private = ec.generate_private_key(curve)
    public = private.public_key()
    return private, public


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def load_public_key(data, curve=ec.SECP256R1()):
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)


def derive_shared_key(private_key, peer_public_key, length=32, info=b'handshake data'):
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(shared)


def encrypt_aes_gcm(key, plaintext, aad=None):
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, plaintext, aad)
    return iv + ct


def decrypt_aes_gcm(key, data, aad=None):
    aesgcm = AESGCM(key)
    iv = data[:12]
    ct = data[12:]
    return aesgcm.decrypt(iv, ct, aad)


def sign_ecdsa(private_key, data):
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_ecdsa(public_key, signature, data):
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
