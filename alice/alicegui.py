# alicegui.py
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

        self.entry = Entry(root, width=60)
        self.entry.pack(padx=10, pady=5)
        self.send_btn = Button(root, text="Send Reply", command=self.send_reply, state=DISABLED)
        self.send_btn.pack(padx=10, pady=5)

        self.conn = None
        self.bob_e = None
        self.bob_n = None

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

            self.conn, addr = s.accept()
            self.log(f"[Alice] Connected by {addr}")

            # Send Alice's public key
            self.conn.sendall(f"{self.e},{self.n}".encode())

            # Receive Bob's public key
            bob_public_key = self.conn.recv(1024).decode()
            self.bob_e, self.bob_n = map(int, bob_public_key.split(','))
            self.log(f"[Alice] Received Bob's Public Key: (e={self.bob_e}, n={self.bob_n})")

            # Receive ciphertext from Bob
            ciphertext_bytes = self.conn.recv(1024)
            ciphertext = int(ciphertext_bytes.decode())
            self.log(f"[Alice] Received Ciphertext: {ciphertext}")

            # Decrypt Bob's message
            decrypted_int = pow(ciphertext, self.d, self.n)
            decrypted_msg = number.long_to_bytes(decrypted_int).decode()
            self.log(f"[Alice] Decrypted Message: {decrypted_msg}")

            # Enable reply
            self.send_btn.config(state=NORMAL)

    def send_reply(self):
        plaintext = self.entry.get()
        if not plaintext:
            self.log("[Alice] Please enter a message to send.")
            return
        # Encrypt with Bob's public key
        m = number.bytes_to_long(plaintext.encode())
        ciphertext_reply = pow(m, self.bob_e, self.bob_n)
        self.conn.sendall(str(ciphertext_reply).encode())
        self.log(f"[Alice] Sent Ciphertext Reply: {ciphertext_reply}")
        self.send_btn.config(state=DISABLED)
        self.entry.delete(0, END)
        self.log("[Alice] Reply sent, waiting for next message...")

    def log(self, message):
        self.text.insert(END, message + '\n')
        self.text.see(END)

if __name__ == "__main__":
    root = Tk()
    app = AliceApp(root)
    root.mainloop()