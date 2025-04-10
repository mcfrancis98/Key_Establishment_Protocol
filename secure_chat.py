from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import time
import json

used_nonces = set()  # Replay protection

# ✅ Encrypt the message using Kabc passed as argument
def encrypt_message(plaintext, Kabc):
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

# ✅ Decrypt the message using Kabc passed as argument
def decrypt_message(nonce, ciphertext, Kabc):
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

# ✅ Prepare the packet by passing Kabc
def prepare_encrypted_packet(plaintext_message, Kabc):
    nonce, ciphertext = encrypt_message(plaintext_message, Kabc)
    return nonce + ciphertext

# ✅ Process received packet by passing Kabc
def process_received_packet(packet_data, Kabc):
    nonce = packet_data[:12]
    ciphertext = packet_data[12:]
    return decrypt_message(nonce, ciphertext, Kabc)
