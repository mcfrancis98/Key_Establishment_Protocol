# auth_manager.py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
import secrets

class AuthManager:
    def __init__(self, entity_name: str, priv_key_path: str, peer_pub_key_path: str = None):
        """
        Initialize with entity name (A/B/C/S) and key paths.
        Args:
            entity_name: Role identifier (e.g., "A", "S").
            priv_key_path: Path to private key (PEM).
            peer_pub_key_path: Path to peer's public key (for verification).
        """
        self.entity = entity_name
        self.priv_key = self._load_key(priv_key_path, private=True)
        self.peer_pub_key = self._load_key(peer_pub_key_path) if peer_pub_key_path else None

    def _load_key(self, path: str, private: bool = False):
        """Load PEM-encoded key (private or public)."""
        with open(path, "rb") as f:
            return load_pem_private_key(f.read(), None) if private else load_pem_public_key(f.read())

    def sign(self, message: bytes) -> bytes:
        """Sign a message with RSA-PSS (SHA-256)."""
        return self.priv_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, message: bytes, signature: bytes, peer_pub_key_path: str = None) -> bool:
        """
        Verify a signature using a peer's public key.
        Args:
            peer_pub_key_path: Override default peer key if needed.
        """
        pub_key = self._load_key(peer_pub_key_path) if peer_pub_key_path else self.peer_pub_key
        try:
            pub_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def generate_challenge(self) -> bytes:
        """Generate a 16-byte nonce for authentication challenges."""
        return secrets.token_bytes(16)

    def authenticate_to_server(self, server_pub_key_path: str) -> tuple:
        """
        Simulate client-to-server authentication.
        Returns:
            (challenge, signature) for the server to verify.
        """
        challenge = self.generate_challenge()
        signature = self.sign(challenge)
        print(f"[{self.entity}] Sent challenge to Server: {challenge.hex()[:8]}...")
        return challenge, signature
