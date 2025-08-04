import socket
from Crypto.Util import number

HOST = 'localhost'
PORT = 65433

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[Bob] Connected to Alice\n")

        # Receive public key
        public_key = s.recv(1024).decode()
        e, n = map(int, public_key.split(','))
        print(f"[Bob] Received Public Key: (e={e}, n={n})")

        # Input plaintext
        plaintext = input("[Bob] Enter message to encrypt: ")
        m = number.bytes_to_long(plaintext.encode())

        # Encrypt
        ciphertext = pow(m, e, n)
        print(f"[Bob] Encrypted Ciphertext: {ciphertext}")

        # Send ciphertext
        s.sendall(str(ciphertext).encode())
        print("[Bob] Ciphertext sent to Alice!")

if __name__ == "__main__":
    start_client()
