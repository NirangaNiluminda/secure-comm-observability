"""
Client-side crypto demo: Shows how a frontend or peer would use the crypto module
to perform ECDH handshake, derive shared keys, and encrypt/decrypt messages.

This demonstrates:
1. Generate ephemeral ECDH keypairs
2. Exchange public keys
3. Derive shared symmetric keys
4. Encrypt messages with AES-GCM
5. Sign messages with ECDSA
6. Verify signatures and decrypt
"""

import crypto
import base64
import json
import hashlib
from cryptography.hazmat.primitives import hashes


def demo_client_server_exchange():
    """Simulate a client-server message exchange with full crypto."""

    print("=" * 70)
    print("SECURE CLIENT-SERVER MESSAGE EXCHANGE DEMO")
    print("=" * 70)

    # ========================================
    # PHASE 1: Key Generation (Alice & Bob)
    # ========================================
    print("\n[PHASE 1] Generate ephemeral keypairs for Alice and Bob")
    alice_ecdh_priv, alice_ecdh_pub = crypto.generate_ec_keypair()
    alice_sign_priv, alice_sign_pub = crypto.generate_ec_keypair()

    bob_ecdh_priv, bob_ecdh_pub = crypto.generate_ec_keypair()
    bob_sign_priv, bob_sign_pub = crypto.generate_ec_keypair()

    # Serialize public keys (as they would be sent to the server)
    alice_ecdh_pub_b64 = base64.b64encode(crypto.serialize_public_key(alice_ecdh_pub)).decode()
    alice_sign_pub_b64 = base64.b64encode(crypto.serialize_public_key(alice_sign_pub)).decode()

    bob_ecdh_pub_b64 = base64.b64encode(crypto.serialize_public_key(bob_ecdh_pub)).decode()
    bob_sign_pub_b64 = base64.b64encode(crypto.serialize_public_key(bob_sign_pub)).decode()

    print(f"  Alice ECDH public (first 16 chars): {alice_ecdh_pub_b64[:16]}...")
    print(f"  Alice ECDSA public (first 16 chars): {alice_sign_pub_b64[:16]}...")
    print(f"  Bob ECDH public (first 16 chars): {bob_ecdh_pub_b64[:16]}...")
    print(f"  Bob ECDSA public (first 16 chars): {bob_sign_pub_b64[:16]}...")

    # ========================================
    # PHASE 2: ECDH Handshake
    # ========================================
    print("\n[PHASE 2] ECDH Handshake: Exchange ephemeral public keys")
    alice_ecdh_peer = crypto.load_public_key(crypto.serialize_public_key(bob_ecdh_pub))
    bob_ecdh_peer = crypto.load_public_key(crypto.serialize_public_key(alice_ecdh_pub))

    # Both parties derive the same shared secret
    alice_shared_secret = crypto.derive_shared_key(
        alice_ecdh_priv, alice_ecdh_peer, info=b'alice-bob'
    )
    bob_shared_secret = crypto.derive_shared_key(
        bob_ecdh_priv, bob_ecdh_peer, info=b'alice-bob'
    )

    assert alice_shared_secret == bob_shared_secret, "Shared secrets do not match!"
    print(f"  ✓ Shared secret derived (length: {len(alice_shared_secret)} bytes)")
    print(f"  ✓ Both parties hold: {alice_shared_secret.hex()[:16]}...")

    # ========================================
    # PHASE 3: Message Encryption & Signing
    # ========================================
    print("\n[PHASE 3] Alice encrypts a message and signs it")

    plaintext = b"Hello Bob, this is a secure message from Alice!"
    print(f"  Original message: {plaintext.decode()}")

    # Alice encrypts using the shared key
    ciphertext_with_iv = crypto.encrypt_aes_gcm(alice_shared_secret, plaintext)
    print(f"  Ciphertext (first 20 bytes): {ciphertext_with_iv[:20].hex()}")

    # Alice signs the ciphertext using her ECDSA private key
    signature = crypto.sign_ecdsa(alice_sign_priv, ciphertext_with_iv)
    print(f"  Signature generated (length: {len(signature)} bytes)")

    # Build the message payload as the server would expect
    message_payload = {
        'from': 'alice',
        'to': 'bob',
        'ciphertext': base64.b64encode(ciphertext_with_iv).decode(),
        'signature': base64.b64encode(signature).decode(),
        'hash': hashlib.sha256(ciphertext_with_iv).hexdigest(),
        'message_id': 'msg-001',
        'sent_at': '2026-05-02T10:00:00Z'
    }
    print(f"  Payload structure: {json.dumps({k: v[:20] + '...' if isinstance(v, str) and len(v) > 20 else v for k, v in message_payload.items()}, indent=2)}")

    # ========================================
    # PHASE 4: Signature Verification (Server)
    # ========================================
    print("\n[PHASE 4] Server verifies Alice's signature before forwarding")
    try:
        ciphertext_bytes = base64.b64decode(message_payload['ciphertext'])
        signature_bytes = base64.b64decode(message_payload['signature'])
        crypto.verify_ecdsa(alice_sign_pub, signature_bytes, ciphertext_bytes)
        print("  ✓ Signature verified successfully!")
    except Exception as e:
        print(f"  ✗ Signature verification failed: {e}")
        return

    # ========================================
    # PHASE 5: Message Decryption (Bob)
    # ========================================
    print("\n[PHASE 5] Bob decrypts the message and verifies sender")
    try:
        decrypted_plaintext = crypto.decrypt_aes_gcm(bob_shared_secret, ciphertext_bytes)
        print(f"  ✓ Decrypted: {decrypted_plaintext.decode()}")
    except Exception as e:
        print(f"  ✗ Decryption failed: {e}")
        return

    # ========================================
    # SUMMARY
    # ========================================
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("✓ Ephemeral ECDH keys generated and exchanged")
    print("✓ Shared symmetric key derived via HKDF")
    print("✓ Message encrypted with AES-256-GCM")
    print("✓ Sender authenticated via ECDSA signature")
    print("✓ Server verified signature and forwarded message")
    print("✓ Recipient decrypted message using shared key")
    print("\nKey properties:")
    print("  - Perfect Forward Secrecy: Ephemeral keys ensure no long-term compromise")
    print("  - Confidentiality: AES-256-GCM encryption")
    print("  - Integrity: AES-GCM authentication tag + ECDSA signature")
    print("  - Non-repudiation: ECDSA signature with sender's public key")
    print("=" * 70)


if __name__ == '__main__':
    demo_client_server_exchange()
