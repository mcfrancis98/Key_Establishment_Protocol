import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# STEP 1: Import key loading functions from Josna's module
from key_manager import load_private_key, load_public_key

# -----------------------------------------------------------------------------
# Francis' Key Exchange Module (Final Improved Version)
# -----------------------------------------------------------------------------
# Securely exchanges signed nonces between 3 clients (A, B, C)
# and derives a shared session key Kabc using HKDF.
# -----------------------------------------------------------------------------

# Constants
NONCE_SIZE = 16
SIG_DELIMITER = b'||'
HKDF_SALT_SIZE = 16
HKDF_KEY_SIZE = 32

# STEP 2: Helper function to load private/public key pair for a given role
def load_my_key_pair(role: str):
    """
    Load private and public key for a given client role ('A', 'B', or 'C').
    Returns: (private_key, public_key)
    """
    priv_path = f"Keys/{role}_priv.pem"
    pub_path = f"Keys/{role}_pub.pem"
    return load_private_key(priv_path), load_public_key(pub_path)

def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)

def sign_nonce(nonce: bytes, private_key) -> bytes:
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
    if len(nonces) != 3:
        raise ValueError("Exactly 3 nonces required to derive Kabc")
    for nonce in nonces:
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Each nonce must be {NONCE_SIZE} bytes")
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
