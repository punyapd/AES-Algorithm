import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

# Key derivation function setup
backend = default_backend()
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)
password = b"mysecretpassword"  # In a real application, use a secure method to handle passwords
key = kdf.derive(password)

def encrypt_text():
    try:
        plain_text = text_input.get("1.0", tk.END).strip()
        if not plain_text:
            messagebox.showerror("Input Error", "Please enter some text to encrypt.")
            return
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        
        encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
        encoded_text = urlsafe_b64encode(iv + encrypted_text).decode()
        
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, encoded_text)
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_text():
    try:
        encrypted_text = text_input.get("1.0", tk.END).strip()
        if not encrypted_text:
            messagebox.showerror("Input Error", "Please enter some text to decrypt.")
            return
        
        decoded_data = urlsafe_b64decode(encrypted_text.encode())
        iv = decoded_data[:16]
        encrypted_data = decoded_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        
        padded_plain_text = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plain_text = unpadder.update(padded_plain_text) + unpadder.finalize()
        
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, plain_text.decode())
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

# Create the main window
root = tk.Tk()
root.title("AES Encrypt and Decrypt Text")

# Create a text input field
text_input = tk.Text(root, height=10, width=50)
text_input.pack(pady=10)

# Create Encrypt and Decrypt buttons
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.pack(side=tk.LEFT, padx=10)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.pack(side=tk.RIGHT, padx=10)

# Create a text field to display the result
result_text = tk.Text(root, height=10, width=50)
result_text.pack(pady=10)

# Start the GUI event loop
root.mainloop()
