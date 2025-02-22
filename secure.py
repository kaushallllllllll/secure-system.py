import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import bcrypt
import base64
import sqlite3
import time

# --- Encryption and Decryption Functions ---

def generate_aes_key():
    return get_random_bytes(16)

def encrypt_message(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_message(encrypted_message, aes_key):
    iv = base64.b64decode(encrypted_message[:24])
    ct = base64.b64decode(encrypted_message[24:])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return decrypted

def encrypt_aes_key(aes_key, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher.encrypt(aes_key)
    return base64.b64encode(encrypted_aes_key).decode('utf-8')

def decrypt_aes_key(encrypted_aes_key, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_aes_key = cipher.decrypt(base64.b64decode(encrypted_aes_key))
    return decrypted_aes_key

# --- User Authentication Functions ---

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(stored_hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

# --- Database Functions ---

def init_db():
    conn = sqlite3.connect('secure_messaging.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            private_key TEXT,
            public_key TEXT
        )
    ''')
    conn.commit()
    conn.close()

def store_user(username, password_hash, private_key, public_key):
    conn = sqlite3.connect('secure_messaging.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO users (username, password_hash, private_key, public_key)
        VALUES (?, ?, ?, ?)
    ''', (username, password_hash, private_key, public_key))
    conn.commit()
    conn.close()

def fetch_user(username):
    conn = sqlite3.connect('secure_messaging.db')
    c = conn.cursor()
    c.execute('''
        SELECT * FROM users WHERE username = ?
    ''', (username,))
    user = c.fetchone()
    conn.close()
    return user

# --- GUI and Application Logic ---

class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messaging Application")
        self.root.geometry("500x400")
        self.current_user = None
        self.aes_key = None
        self.messages = []  # Store messages here for persistence
        self.username_entry = None
        self.password_entry = None
        self.message_entry = None
        self.create_login_screen()

    def create_login_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="Username:").pack(pady=10)
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack(pady=10)

        tk.Label(self.root, text="Password:").pack(pady=10)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=10)

        tk.Button(self.root, text="Login", command=self.login).pack(pady=20)
        tk.Button(self.root, text="Register", command=self.create_register_screen).pack(pady=20)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        user = fetch_user(username)

        if user and verify_password(user[1], password):
            self.current_user = user
            self.aes_key = generate_aes_key()
            self.create_chat_screen()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def create_register_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="Username:").pack(pady=10)
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack(pady=10)

        tk.Label(self.root, text="Password:").pack(pady=10)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=10)

        tk.Button(self.root, text="Register", command=self.register).pack(pady=20)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Registration Failed", "Please fill in all fields")
            return

        if fetch_user(username):
            messagebox.showerror("Registration Failed", "Username already exists")
            return

        password_hash = hash_password(password)
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()

        store_user(username, password_hash, private_key.export_key().decode('utf-8'), public_key.export_key().decode('utf-8'))

        messagebox.showinfo("Registration Success", "User registered successfully")
        self.create_login_screen()

    def create_chat_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="Chat Room", font=("Arial", 20)).pack(pady=20)

        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack(pady=10)

        tk.Button(self.root, text="Send", command=self.send_message).pack(pady=20)
        tk.Button(self.root, text="Logout", command=self.logout).pack(pady=10)

        self.chat_window = tk.Text(self.root, height=10, width=50)
        self.chat_window.pack(pady=10)

        self.refresh_chat()

        # Simulate the other user sending a message after a delay
        self.root.after(3000, self.simulate_receive_message)

    def send_message(self):
        message = self.message_entry.get()
        if message:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())  # Get the current local timestamp
            encrypted_message = encrypt_message(message, self.aes_key)
            self.messages.append(('sent', message, encrypted_message, timestamp))  # Save message

            # Show both encrypted and plaintext messages
            self.chat_window.insert(tk.END, f"{timestamp} You (Plaintext): {message}\n")
            self.chat_window.insert(tk.END, f"{timestamp} You (Encrypted): {encrypted_message}\n")

            # Clear the message entry box
            self.message_entry.delete(0, tk.END)

    def simulate_receive_message(self):
        received_message = "Hello, how are you?"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())  # Get the current local timestamp
        encrypted_received_message = encrypt_message(received_message, self.aes_key)
        self.messages.append(('received', received_message, encrypted_received_message, timestamp))  # Save message

        # Display the received encrypted and plaintext message
        self.chat_window.insert(tk.END, f"{timestamp} Friend (Plaintext): {received_message}\n")
        self.chat_window.insert(tk.END, f"{timestamp} Friend (Encrypted): {encrypted_received_message}\n")

    def logout(self):
        self.current_user = None
        self.aes_key = None
        self.create_login_screen()

    def refresh_chat(self):
        for msg in self.messages:
            timestamp = msg[3]
            if msg[0] == 'sent':
                self.chat_window.insert(tk.END, f"{timestamp} You (Plaintext): {msg[1]}\n")
                self.chat_window.insert(tk.END, f"{timestamp} You (Encrypted): {msg[2]}\n")
            elif msg[0] == 'received':
                self.chat_window.insert(tk.END, f"{timestamp} Friend (Plaintext): {msg[1]}\n")
                self.chat_window.insert(tk.END, f"{timestamp} Friend (Encrypted): {msg[2]}\n")

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

# Run the app
if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()
