import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# -----------------------------------------------------------------------------
# Francis' Key Exchange Module (Final Improved Version)
# -----------------------------------------------------------------------------
# Securely exchanges signed nonces between 3 clients (A, B, C)
# and derives a shared session key Kabc using HKDF.
# -----------------------------------------------------------------------------

# Constants
NONCE_SIZE = 16
SIG_DELIMITER = b'||'  # Delimiter to separate nonce and signature
HKDF_SALT_SIZE = 16
HKDF_KEY_SIZE = 32  # AES-256

def generate_nonce() -> bytes:
    """
    Generate a secure 16-byte random nonce.
    Returns:
        bytes: 16-byte nonce
    """
    return os.urandom(NONCE_SIZE)

def sign_nonce(nonce: bytes, private_key) -> bytes:
    """
    Sign the nonce with the client's RSA private key.
    Args:
        nonce: 16-byte nonce to sign
        private_key: RSAPrivateKey object
    Returns:
        bytes: Signature of nonce
    Raises:
        ValueError: If nonce size is incorrect
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")

    return private_key.sign(
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def encrypt_for_peer(nonce: bytes, signature: bytes, peer_pubkey) -> bytes:
    """
    Encrypt signed nonce using peer's RSA public key with OAEP.
    Args:
        nonce: 16-byte nonce
        signature: signature of nonce
        peer_pubkey: recipient's RSAPublicKey
    Returns:
        bytes: Encrypted message to send via server
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")
    if not signature:
        raise ValueError("Signature cannot be empty")

    message = nonce + SIG_DELIMITER + signature
    return peer_pubkey.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_and_verify(encrypted_msg: bytes, own_privkey, sender_pubkey) -> bytes:
    """
    Decrypt and verify an incoming encrypted nonce+signature.
    Args:
        encrypted_msg: RSA-OAEP encrypted message
        own_privkey: RSAPrivateKey to decrypt
        sender_pubkey: RSAPublicKey to verify signature
    Returns:
        bytes: Verified nonce if successful
    Raises:
        ValueError: On decryption or verification failure
    """
    try:
        decrypted = own_privkey.decrypt(
            encrypted_msg,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        parts = decrypted.split(SIG_DELIMITER, 1)
        if len(parts) != 2:
            raise ValueError("Invalid message format: delimiter missing")
        
        nonce, signature = parts
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Invalid nonce length (expected {NONCE_SIZE} bytes)")

        sender_pubkey.verify(
            signature,
            nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return nonce

    except Exception as e:
        raise ValueError(f"Decryption/verification failed: {str(e)}")

def derive_kabc(nonces: list[bytes]) -> bytes:
    """
    Derive the shared session key Kabc from three nonces using HKDF.
    The salt is derived deterministically from the hash of all nonces
    to ensure that A, B, and C derive the exact same key independently.
    Args:
        nonces: list of exactly three 16-byte nonces [r_a, r_b, r_c]
    Returns:
        bytes: 32-byte AES key
    Raises:
        ValueError: If input is invalid
    """
    if len(nonces) != 3:
        raise ValueError("Exactly 3 nonces required to derive Kabc")

    for nonce in nonces:
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Each nonce must be {NONCE_SIZE} bytes")

    # Derive a fixed salt using SHA-256 hash of the combined nonces
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"".join(nonces))
    salt = digest.finalize()[:HKDF_SALT_SIZE]

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_KEY_SIZE,
        salt=salt,
        info=b'kabc-derivation'
    )
    return hkdf.derive(b"".join(nonces))
