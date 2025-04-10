import socket
import threading
import json
import time

CLIENT_ID = "A"
SERVER_HOST = 'localhost'
SERVER_PORT = 12345

def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(4096)
            if msg:
                data = json.loads(msg.decode())
                print(f"[{data['sender']}]: {data['ciphertext']} (nonce: {data['nonce']})")
        except:
            break

def send_message(sock):
    while True:
        plaintext = input("> ")
        secure_payload = {
            "sender": CLIENT_ID,
            "timestamp": int(time.time()),
            "nonce": "random_nonce_placeholder",
            "ciphertext": f"encrypted({plaintext})"
        }
        msg = json.dumps(secure_payload).encode()
        sock.send(msg)

def main():
    sock = socket.socket()
    sock.connect((SERVER_HOST, SERVER_PORT))
    sock.send(CLIENT_ID.encode())

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()
    send_message(sock)

if __name__ == "__main__":
    main()
