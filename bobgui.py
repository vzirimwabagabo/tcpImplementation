#bobgui.py
import socket
from tkinter import *
from Crypto.Util import number
import threading

HOST = 'localhost'
PORT = 65434

class Bob:
    def __init__(self, root):
        self.root = root
        self.root.title("Bob - RSA Client")

        self.text = Text(root, height=20, width=80)
        self.text.pack(padx=10, pady=10)

        self.entry = Entry(root, width=60)
        self.entry.pack(pady=5)

        self.button = Button(root, text="Encrypt & Send", command=self.send_message)
        self.button.pack(pady=5)

        self.e = None
        self.n = None
        self.s = None

        self.log("[Bob] Generating RSA keys...")
        self.be, self.bd, self.bn = self.generate_keys()
        self.log(f"[Bob] Public Key: (e={self.be}, n={self.bn})")
        self.log(f"[Bob] Private Key: d={self.bd}")

        self.log("[Bob] Connecting to Alice...")
        self.connect_to_alice()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def generate_keys(self):
        bit_length = 512
        e = 65537
        p = number.getPrime(bit_length)
        q = number.getPrime(bit_length)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        return e, d, n

    def connect_to_alice(self):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((HOST, PORT))
            self.log("[Bob] Connected!")

            # Receive Alice's public key
            public_key = self.s.recv(1024).decode()
            self.e, self.n = map(int, public_key.split(','))
            self.log(f"[Bob] Received Alice's Public Key: (e={self.e}, n={self.n})")

            # Send Bob's public key to Alice
            self.s.sendall(f"{self.be},{self.bn}".encode())
            self.log("[Bob] Sent public key to Alice.")
        except Exception as e:
            self.log(f"[Bob] Connection failed: {e}")

    def send_message(self):
        msg = self.entry.get()
        if not msg or not self.e or not self.n:
            self.log("[Bob] Please enter a message before sending.")
            return

        m = number.bytes_to_long(msg.encode())
        cipher = pow(m, self.e, self.n)
        self.log(f"[Bob] Ciphertext: {cipher}")
        try:
            self.s.sendall(str(cipher).encode())
            self.log("[Bob] Message sent!")
        except Exception as e:
            self.log(f"[Bob] Error sending message: {e}")
            return

        threading.Thread(target=self.receive_reply, daemon=True).start()

    def receive_reply(self):
        try:
            reply_bytes = self.s.recv(1024)
            reply_str = reply_bytes.decode()
            if not reply_str:
                self.log("[Bob] No reply received from Alice.")
                return
            reply_cipher = int(reply_str)
            self.log(f"[Bob] Received Ciphertext Reply: {reply_cipher}")

            # Decrypt Alice's reply using Bob's private key
            reply_plain_int = pow(reply_cipher, self.bd, self.bn)
            try:
                reply_plain = number.long_to_bytes(reply_plain_int).decode()
            except Exception:
                reply_plain = "[Bob] Could not decode reply to text."
            self.log(f"[Bob] Decrypted Reply: {reply_plain}")
        except Exception as e:
            self.log(f"[Bob] Error receiving reply: {e}")

    def on_close(self):
        if self.s:
            try:
                self.s.close()
            except Exception:
                pass
        self.root.destroy()

    def log(self, message):
        self.text.insert(END, message + '\n')
        self.text.see(END)

if __name__ == "__main__":
    root = Tk()
    app = Bob(root)
    root.mainloop()