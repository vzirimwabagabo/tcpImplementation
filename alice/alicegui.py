import socket
import threading
from tkinter import *
from Crypto.Util import number

HOST = 'localhost'
PORT = 65434

class AliceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Alice - RSA Server")

        self.text = Text(root, height=20, width=80)
        self.text.pack(padx=10, pady=10)

        self.log("[Alice] Generating RSA keys...")
        self.e, self.d, self.n = self.generate_keys()
        self.log(f"[Alice] Public Key: (e={self.e}, n={self.n})")
        self.log(f"[Alice] Private Key: d={self.d}")
        self.log("\n[Alice] Starting server...")

        threading.Thread(target=self.start_server, daemon=True).start()

    def generate_keys(self):
        bit_length = 512
        e = 65537
        p = number.getPrime(bit_length)
        q = number.getPrime(bit_length)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        return e, d, n

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(1)
            self.log(f"\n[Alice] Listening on {HOST}:{PORT}...")

            conn, addr = s.accept()
            with conn:
                self.log(f"[Alice] Connected by {addr}")

                # Send public key
                conn.sendall(f"{self.e},{self.n}".encode())

                # Receive ciphertext
                ciphertext_bytes = conn.recv(1024)
                ciphertext = int(ciphertext_bytes.decode())
                self.log(f"[Alice] Received Ciphertext: {ciphertext}")

                # Decrypt
                decrypted_int = pow(ciphertext, self.d, self.n)
                decrypted_msg = number.long_to_bytes(decrypted_int).decode()
                self.log(f"[Alice] Decrypted Message: {decrypted_msg}")

    def log(self, message):
        self.text.insert(END, message + '\n')
        self.text.see(END)

if __name__ == "__main__":
    root = Tk()
    app = AliceApp(root)
    root.mainloop()
