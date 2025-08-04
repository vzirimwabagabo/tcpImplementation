import socket
from Crypto.Util import number

HOST = 'localhost'
PORT = 65433

# RSA Key Generation
def generate_keys():
    bit_length = 512
    e = 65537

    p = number.getPrime(bit_length)
    q = number.getPrime(bit_length)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Compute d
    d = pow(e, -1, phi)
    return e, d, n

def start_server():
    e, d, n = generate_keys()
    print(f"[Alice] Public Key: (e={e}, n={n})")
    print(f"[Alice] Private Key: d={d}\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Alice] Listening on {HOST}:{PORT}...\n")

        conn, addr = s.accept()
        with conn:
            print(f"[Alice] Connected by {addr}")
            
            # Send public key to Bob
            conn.sendall(f"{e},{n}".encode())

            # Receive ciphertext
            ciphertext_bytes = conn.recv(1024)
            ciphertext = int(ciphertext_bytes.decode())
            print(f"[Alice] Received Ciphertext: {ciphertext}")

            # Decrypt
            decrypted_int = pow(ciphertext, d, n)
            decrypted_msg = number.long_to_bytes(decrypted_int).decode()
            print(f"[Alice] Decrypted Message: {decrypted_msg}")

if __name__ == "__main__":
    start_server()
