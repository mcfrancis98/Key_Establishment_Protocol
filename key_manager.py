import os
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key, load_pem_public_key
)
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding

def generate_rsa_keypair(name: str, key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate and save RSA key pair with robust error handling"""
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=None
        )
        
        # Save private key with strict permissions
        priv_path = f"keys/{name}_priv.pem"
        with open(priv_path, "wb") as f:
            os.chmod(priv_path, 0o600)  # -rw-------
            f.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))
        
        # Save public key
        pub_path = f"keys/{name}_pub.pem"
        with open(pub_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ))
            
        return private_key
        
    except Exception as e:
        print(f"❌ Key generation failed for {name}: {str(e)}")
        raise

def generate_self_signed_cert(name: str, private_key: rsa.RSAPrivateKey):
    """Generate and save X.509 certificate with proper validity checks"""
    try:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{name}.securechat.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Inc."),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=1)  # 1 day grace period
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).sign(private_key, hashes.SHA256())
        
        cert_path = f"keys/cert_{name}.pem"
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))
            
    except Exception as e:
        print(f"❌ Certificate generation failed for {name}: {str(e)}")
        raise

def verify_key_integrity(name: str) -> bool:
    """Verify generated keys are valid and match"""
    try:
        # Load private key
        with open(f"keys/{name}_priv.pem", "rb") as f:
            priv_key = load_pem_private_key(f.read(), password=None)
        
        # Load public key
        with open(f"keys/{name}_pub.pem", "rb") as f:
            pub_key = load_pem_public_key(f.read())
            
        # Verify they form a valid pair
        test_msg = b"INTEGRITY TEST"
        signature = priv_key.sign(
            test_msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        
        pub_key.verify(
            signature,
            test_msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        return True
        
    except Exception as e:
        print(f"❌ Key integrity check failed for {name}: {str(e)}")
        return False

def main():
    """Main key generation routine with comprehensive checks"""
    try:
        os.makedirs("keys", exist_ok=True)
        os.chmod("keys", 0o700)  # drwx------
        
        print("🔑 Generating RSA key pairs and certificates...")
        entities = ["A", "B", "C", "S"]
        
        for entity in entities:
            print(f"\nGenerating keys for {entity}:")
            priv_key = generate_rsa_keypair(entity)
            generate_self_signed_cert(entity, priv_key)
            
            if verify_key_integrity(entity):
                print(f"✅ {entity} keys validated successfully")
            else:
                raise RuntimeError(f"Key validation failed for {entity}")
                
        print("\n🎉 All keys and certificates generated successfully!")
        
    except Exception as e:
        print(f"\n❌ Critical error in key generation: {str(e)}")
        raise

if __name__ == "__main__":
    main()
