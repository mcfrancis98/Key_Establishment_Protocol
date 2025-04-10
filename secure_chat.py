from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import time
import json
from key_exchange import derive_kabc  # ✅ Clean import

# Get session key from Francis's function
Kabc = derive_kabc()

used_nonces = set()  # Replay protection

def encrypt_message(plaintext):
    aesgcm = AESGCM(Kabc)
    nonce = os.urandom(12)
    timestamp = int(time.time())
    data = {
        "timestamp": timestamp,
        "message": plaintext
    }
    plaintext_bytes = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce, ciphertext

def decrypt_message(nonce, ciphertext):
    aesgcm = AESGCM(Kabc)
    if nonce in used_nonces:
        raise ValueError("Replay attack detected! Nonce has already been used.")
    used_nonces.add(nonce)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext_bytes.decode())
        current_time = int(time.time())
        if abs(current_time - data["timestamp"]) > 60:
            print("Warning: Message timestamp is old!")
        return data['message']
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def prepare_encrypted_packet(plaintext_message):
    nonce, ciphertext = encrypt_message(plaintext_message)
    return nonce + ciphertext

def process_received_packet(packet_data):
    nonce = packet_data[:12]
    ciphertext = packet_data[12:]
    return decrypt_message(nonce, ciphertext)
