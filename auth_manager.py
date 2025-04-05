from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key
)
from cryptography.exceptions import InvalidSignature
import hashlib
import secrets
import os

class AuthManager:
    def __init__(self, entity_name: str, priv_key_path: str, peer_pub_key_path: Optional[str] = None):
        """Initialize authentication with strict key validation"""
        self.entity = entity_name
        self.priv_key = self._load_private_key(priv_key_path)
        self.peer_pub_key = self._load_public_key(peer_pub_key_path) if peer_pub_key_path else None
        
        # Verify keys are valid on initialization
        self._verify_key_pair()

    def _load_private_key(self, path: str) -> rsa.RSAPrivateKey:
        """Load private key with robust error handling and logging"""
        try:
            print(f"🔑 Loading private key from {path}...")
            if not os.path.exists(path):
                raise FileNotFoundError(f"Private key file not found at {path}")
                
            with open(path, "rb") as f:
                key_data = f.read()
                key = load_pem_private_key(key_data, password=None)
                
                if not isinstance(key, rsa.RSAPrivateKey):
                    raise ValueError("Not an RSA private key")
                    
                print(f"✅ Private key loaded successfully from {path}")
                return key
                
        except Exception as e:
            print(f"❌ Failed to load private key from {path}: {str(e)}")
            raise

    def _load_public_key(self, path: str) -> rsa.RSAPublicKey:
        """Load public key with strict validation and logging"""
        try:
            print(f"🔑 Loading public key from {path}...")
            if not os.path.exists(path):
                raise FileNotFoundError(f"Public key file not found at {path}")
                
            with open(path, "rb") as f:
                key_data = f.read()
                key = load_pem_public_key(key_data)
                
                if not isinstance(key, rsa.RSAPublicKey):
                    raise ValueError("Not an RSA public key")
                    
                print(f"✅ Public key loaded successfully from {path}")
                return key
                
        except Exception as e:
            print(f"❌ Failed to load public key from {path}: {str(e)}")
            raise

    def _verify_key_pair(self):
        """Verify the private and public keys form a valid pair"""
        test_msg = b"KEY PAIR VALIDATION TEST MESSAGE"
        try:
            print(f"\n🔍 Verifying key pair for {self.entity}...")
            
            # Get public key from private key
            derived_pub_key = self.priv_key.public_key()
            print(f"🔍 Derived public key from private key")
            
            # Sign the test message
            print(f"🔍 Signing test message: {test_msg.hex()[:16]}...")
            signature = self._sign_with_pss(test_msg)
            print(f"🔍 Signature created (hex): {signature.hex()[:16]}...")
            
            # Verify the signature
            print(f"🔍 Verifying signature...")
            self._verify_with_pss(test_msg, signature, derived_pub_key)
            print(f"✅ Key pair validation successful for {self.entity}")
            
        except Exception as e:
            print(f"❌ Key pair validation failed for {self.entity}: {str(e)}")
            raise

    def _sign_with_pss(self, message: bytes) -> bytes:
        """Sign message with RSA-PSS using standardized parameters"""
        return self.priv_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def _verify_with_pss(self, message: bytes, signature: bytes, public_key: rsa.RSAPublicKey):
        """Verify signature with RSA-PSS using standardized parameters"""
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def sign(self, message: bytes) -> bytes:
        """Public method to sign messages"""
        return self._sign_with_pss(message)

    def verify(self, message: bytes, signature: bytes, peer_pub_key_path: Optional[str] = None) -> bool:
        """Public method to verify signatures"""
        try:
            pub_key = self._load_public_key(peer_pub_key_path) if peer_pub_key_path else self.peer_pub_key
            self._verify_with_pss(message, signature, pub_key)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"❌ Verification error: {str(e)}")
            return False

    def generate_nonce(self) -> bytes:
        """Generate cryptographically secure nonce"""
        return secrets.token_bytes(16) + hashlib.sha256(self.entity.encode()).digest()[:8]

    def perform_handshake(self, peer_pub_key_path: str) -> Tuple[bool, str]:
        """Perform mutual authentication with detailed status reporting"""
        try:
            print(f"\n🔐 [{self.entity}] Starting handshake...")
            
            # Step 1: Generate and sign nonce
            our_nonce = self.generate_nonce()
            our_sig = self.sign(our_nonce)
            print(f"[{self.entity}] Generated nonce: {our_nonce.hex()[:12]}...")
            print(f"[{self.entity}] Created signature: {our_sig.hex()[:16]}...")
            
            # Step 2: Determine peer type and load appropriate keys
            if self.entity in ["A", "B", "C"]:  # We're a client, peer is server
                peer_entity = "S"
                peer_priv_path = "keys/S_priv.pem"
                verification_key_path = "keys/A_pub.pem"
            else:  # We're the server, peer is client
                peer_entity = "A"  # Default to client A
                peer_priv_path = "keys/A_priv.pem"
                verification_key_path = "keys/S_pub.pem"
            
            print(f"[{self.entity}] Initializing peer ({peer_entity}) authentication...")
            
            # Step 3: Verify our signature using peer's verification
            print(f"[{self.entity}] Verifying our signature with peer...")
            verification_pub_key = self._load_public_key(verification_key_path)
            try:
                verification_pub_key.verify(
                    our_sig,
                    our_nonce,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f"[{self.entity}] Our signature verified successfully by peer")
            except InvalidSignature:
                return False, "Peer failed to verify our signature"
            
            # Step 4: Get peer's nonce and verify it
            print(f"[{self.entity}] Generating peer nonce and signature...")
            peer_auth = AuthManager(
                entity_name=peer_entity,
                priv_key_path=peer_priv_path,
                peer_pub_key_path=peer_pub_key_path
            )
            
            peer_nonce = peer_auth.generate_nonce()
            peer_sig = peer_auth.sign(peer_nonce)
            print(f"[{self.entity}] Received peer nonce: {peer_nonce.hex()[:12]}...")
            print(f"[{self.entity}] Peer signature: {peer_sig.hex()[:16]}...")
            
            if not self.verify(peer_nonce, peer_sig, peer_pub_key_path):
                return False, "Failed to verify peer's signature"
                
            print(f"[{self.entity}] Handshake completed successfully")
            return True, "Success"
            
        except Exception as e:
            return False, f"Handshake error: {str(e)}"

if __name__ == "__main__":
    print("🔍 Starting the authentication manager script...")
    try:
        # Initialize authentication for client A
        print("\n=== Testing Client Authentication ===")
        client_auth = AuthManager(
            entity_name="A",
            priv_key_path="keys/A_priv.pem",
            peer_pub_key_path="keys/S_pub.pem"
        )
        success, message = client_auth.perform_handshake("keys/S_pub.pem")
        
        if success:
            print("✅ Client authentication succeeded!")
        else:
            print(f"❌ Client authentication failed: {message}")

        # Initialize authentication for server S
        print("\n=== Testing Server Authentication ===")
        server_auth = AuthManager(
            entity_name="S",
            priv_key_path="keys/S_priv.pem",
            peer_pub_key_path="keys/A_pub.pem"
        )
        success, message = server_auth.perform_handshake("keys/A_pub.pem")
        
        if success:
            print("✅ Server authentication succeeded!")
        else:
            print(f"❌ Server authentication failed: {message}")

    except Exception as e:
        print(f"❌ An error occurred: {str(e)}")
