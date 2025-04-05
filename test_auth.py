# test_auth.py
from auth_manager import AuthManager

# Initialize entities
client_a = AuthManager("A", "A_priv.pem", "S_pub.pem")
server_s = AuthManager("S", "S_priv.pem", "A_pub.pem")

# Client A authenticates to Server S
challenge, signature = client_a.authenticate_to_server("S_pub.pem")
if server_s.verify(challenge, signature):
    print("[Server] ✅ Verified A's identity!")
    # Server responds with its own challenge
    s_challenge = server_s.generate_challenge()
    s_signature = server_s.sign(s_challenge)
    if client_a.verify(s_challenge, s_signature, "S_pub.pem"):
        print("[A] ✅ Verified Server's identity!")
        print("🎉 Mutual authentication successful!")
    else:
        print("[A] ❌ Server authentication failed!")
else:
    print("[Server] ❌ A's authentication failed!")
