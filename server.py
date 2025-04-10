import socket
import threading
import json

clients = {}  # {client_id: socket}

def handle_client(conn, client_id):
    while True:
        try:
            msg = conn.recv(4096)
            if not msg:
                break
            forward_to_others(msg, sender=client_id)
        except:
            break
    print(f"[!] {client_id} disconnected")
    del clients[client_id]
    conn.close()

def forward_to_others(msg, sender):
    for cid, sock in clients.items():
        if cid != sender:
            try:
                sock.send(msg)
            except:
                print(f"[!] Failed to send to {cid}")

def start_server(host='localhost', port=12345):
    server = socket.socket()
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Server listening on {host}:{port}")

    while len(clients) < 3:
        conn, addr = server.accept()
        client_id = conn.recv(1024).decode().strip()
        clients[client_id] = conn
        print(f"[+] {client_id} connected from {addr}")
        threading.Thread(target=handle_client, args=(conn, client_id), daemon=True).start()

if __name__ == "__main__":
    start_server()
