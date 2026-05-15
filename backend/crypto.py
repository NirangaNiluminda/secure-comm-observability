import base64
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicNumbers, SECP256R1
)


# ── Key generation ────────────────────────────────────────────

def generate_ec_keypair(curve=ec.SECP256R1()):
    private = ec.generate_private_key(curve)
    return private, private.public_key()


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def load_public_key(data: bytes, curve=ec.SECP256R1()):
    """Load from raw X9.62 uncompressed point bytes (04 || x || y)."""
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)


def load_public_key_from_jwk(jwk: dict, curve=ec.SECP256R1()) -> ec.EllipticCurvePublicKey:
    """
    Load an EC public key from a JWK dict as exported by the browser Web Crypto API.

    Web Crypto exports P-256 keys as:
      { kty:'EC', crv:'P-256', x:'<base64url>', y:'<base64url>', ... }

    The x / y values are base64url-encoded big-endian integers (32 bytes each for P-256).
    """
    def _b64url_decode(s: str) -> bytes:
        # Restore standard base64 padding
        s += '=' * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    x = int.from_bytes(_b64url_decode(jwk['x']), 'big')
    y = int.from_bytes(_b64url_decode(jwk['y']), 'big')
    return EllipticCurvePublicNumbers(x=x, y=y, curve=curve).public_key()


# ── Key derivation ────────────────────────────────────────────

def derive_shared_key(private_key, peer_public_key, length=32, info=b'handshake data'):
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(shared)


# ── AES-256-GCM ───────────────────────────────────────────────

def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
    iv = os.urandom(12)
    return iv + AESGCM(key).encrypt(iv, plaintext, aad)


def decrypt_aes_gcm(key: bytes, data: bytes, aad: bytes = None) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], aad)


# ── ECDSA ─────────────────────────────────────────────────────

def _p1363_to_der(sig_bytes: bytes) -> bytes:
    """
    Convert an IEEE P1363 signature (r ‖ s, fixed-length) to DER format.

    Web Crypto API (SubtleCrypto.sign with ECDSA) produces P1363.
    Python's cryptography library expects DER for verify().
    For P-256 keys, P1363 is always 64 bytes (32 r + 32 s).
    """
    half = len(sig_bytes) // 2
    r = int.from_bytes(sig_bytes[:half], 'big')
    s = int.from_bytes(sig_bytes[half:], 'big')

    def _encode_int(n: int) -> bytes:
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:           # prepend 0x00 if high bit set (DER rule)
            b = b'\x00' + b
        return b

    r_enc = _encode_int(r)
    s_enc = _encode_int(s)
    inner  = bytes([0x02, len(r_enc)]) + r_enc + bytes([0x02, len(s_enc)]) + s_enc
    return  bytes([0x30, len(inner)]) + inner


def sign_ecdsa(private_key, data: bytes) -> bytes:
    """Sign data; returns DER-encoded signature."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_ecdsa(public_key, signature: bytes, data: bytes) -> None:
    """
    Verify an ECDSA signature.
    Accepts both DER (from Python sign_ecdsa) and P1363 (from Web Crypto).
    Raises cryptography.exceptions.InvalidSignature on failure.
    """
    # Detect P1363: DER sequences start with 0x30; P1363 for P-256 is 64 bytes
    if len(signature) == 64 and signature[0] != 0x30:
        signature = _p1363_to_der(signature)
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
