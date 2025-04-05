from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

def test_key_pair(private_key_path, public_key_path):
    try:
        # Load private key
        with open(private_key_path, "rb") as f:
            priv_key = load_pem_private_key(f.read(), password=None)

        # Load public key
        with open(public_key_path, "rb") as f:
            pub_key = load_pem_public_key(f.read())
        
        # Generate test message
        test_message = b"Test message for key pair validation"
        
        # Sign the message with the private key
        signature = priv_key.sign(
            test_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        
        # Verify the signature with the public key
        pub_key.verify(
            signature,
            test_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        
        print("✅ Keys are valid and match!")
        
    except InvalidSignature:
        print("❌ Signature verification failed. Keys do not match.")
    except Exception as e:
        print(f"❌ Error during key verification: {str(e)}")

# Test the key pair for A
test_key_pair("keys/A_priv.pem", "keys/A_pub.pem")
