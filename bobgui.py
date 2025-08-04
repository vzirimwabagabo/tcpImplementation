# bob_gui.py
import socket
from tkinter import *
from Crypto.Util import number

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
        self.button.pack()

        self.e = None
        self.n = None

        self.log("[Bob] Connecting to Alice...")
        self.connect_to_alice()

    def connect_to_alice(self):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((HOST, PORT))
            self.log("[Bob] Connected!")

            public_key = self.s.recv(1024).decode()
            self.e, self.n = map(int, public_key.split(','))
            self.log(f"[Bob] Received Public Key: (e={self.e}, n={self.n})")
        except Exception as e:
            self.log(f"[Bob] Connection failed: {e}")

    def send_message(self):
        msg = self.entry.get()
        if not msg or not self.e or not self.n:
            return

        m = number.bytes_to_long(msg.encode())
        cipher = pow(m, self.e, self.n)
        self.log(f"[Bob] Ciphertext: {cipher}")
        self.s.sendall(str(cipher).encode())
        self.log("[Bob] Message sent!")

    def log(self, message):
        self.text.insert(END, message + '\n')
        self.text.see(END)

if __name__ == "__main__":
    root = Tk()
    app = Bob(root)
    root.mainloop()
# This code implements a simple GUI for Bob in the RSA encryption demo.
# It connects to Alice's server, receives her public key, and allows Bob to input a message to encrypt and send.
# The GUI uses Tkinter for the interface and displays logs of actions taken.