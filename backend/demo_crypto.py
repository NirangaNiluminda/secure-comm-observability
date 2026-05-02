"""Small demo showing ephemeral ECDH, AES-GCM encryption, and ECDSA signing.

Run this from the `backend/` directory with the project's Python environment active.
"""
import crypto


def demo():
    # Generate ephemeral keypairs for Alice and Bob
    a_priv, a_pub = crypto.generate_ec_keypair()
    b_priv, b_pub = crypto.generate_ec_keypair()

    # Exchange public keys (serialize/deserialize)
    a_pub_bytes = crypto.serialize_public_key(a_pub)
    b_pub_bytes = crypto.serialize_public_key(b_pub)
    a_peer = crypto.load_public_key(b_pub_bytes)
    b_peer = crypto.load_public_key(a_pub_bytes)

    # Derive shared symmetric keys (should be identical)
    a_key = crypto.derive_shared_key(a_priv, a_peer)
    b_key = crypto.derive_shared_key(b_priv, b_peer)

    assert a_key == b_key, "Derived keys do not match"

    message = b"Hello, secure world"

    # Alice encrypts and signs the ciphertext
    ciphertext = crypto.encrypt_aes_gcm(a_key, message)
    signature = crypto.sign_ecdsa(a_priv, ciphertext)

    # Bob verifies signature and decrypts
    crypto.verify_ecdsa(a_pub, signature, ciphertext)
    plaintext = crypto.decrypt_aes_gcm(b_key, ciphertext)

    print("Decrypted message:", plaintext)


if __name__ == '__main__':
    demo()
