import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class EncryptionTool:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Encryption/Decryption Tool")
        self.window.geometry("600x400")
        
        # Method selection
        self.method_frame = ttk.LabelFrame(self.window, text="Encryption Method")
        self.method_frame.pack(padx=10, pady=5, fill="x")
        
        self.method = tk.StringVar(value="caesar")
        ttk.Radiobutton(self.method_frame, text="Caesar Cipher", value="caesar", 
                       variable=self.method, command=self.update_key_entry).pack(side="left", padx=5)
        ttk.Radiobutton(self.method_frame, text="Vigenère Cipher", value="vigenere", 
                       variable=self.method, command=self.update_key_entry).pack(side="left", padx=5)
        ttk.Radiobutton(self.method_frame, text="AES (Fernet)", value="aes", 
                       variable=self.method, command=self.update_key_entry).pack(side="left", padx=5)

        # Key/Password entry
        self.key_frame = ttk.LabelFrame(self.window, text="Key/Password")
        self.key_frame.pack(padx=10, pady=5, fill="x")
        self.key_entry = ttk.Entry(self.key_frame)
        self.key_entry.pack(padx=5, pady=5, fill="x")
        
        # Message entry
        self.message_frame = ttk.LabelFrame(self.window, text="Message")
        self.message_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.message_text = tk.Text(self.message_frame, height=8)
        self.message_text.pack(padx=5, pady=5, fill="both", expand=True)
        
        # Buttons
        self.button_frame = ttk.Frame(self.window)
        self.button_frame.pack(padx=10, pady=5, fill="x")
        ttk.Button(self.button_frame, text="Encrypt", command=self.encrypt).pack(side="left", padx=5)
        ttk.Button(self.button_frame, text="Decrypt", command=self.decrypt).pack(side="left", padx=5)
        
        # Result
        self.result_frame = ttk.LabelFrame(self.window, text="Result")
        self.result_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.result_text = tk.Text(self.result_frame, height=8)
        self.result_text.pack(padx=5, pady=5, fill="both", expand=True)

    def update_key_entry(self):
        method = self.method.get()
        if method == "caesar":
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, "3")
            self.key_entry.config(state="normal")
        elif method == "vigenere":
            self.key_entry.config(state="normal")
        else:  # AES
            self.key_entry.config(state="normal")

    def caesar_cipher(self, text, shift, decrypt=False):
        if decrypt:
            shift = -int(shift)
        else:
            shift = int(shift)
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result

    def vigenere_cipher(self, text, key, decrypt=False):
        result = ""
        key = key.upper()
        key_length = len(key)
        key_as_int = [ord(i) - ord('A') for i in key]
        text_int = [ord(i) for i in text]
        for i in range(len(text)):
            if text[i].isalpha():
                if decrypt:
                    shift = -key_as_int[i % key_length]
                else:
                    shift = key_as_int[i % key_length]
                if text[i].isupper():
                    result += chr((text_int[i] - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += chr((text_int[i] - ord('a') + shift) % 26 + ord('a'))
            else:
                result += text[i]
        return result

    def get_fernet_key(self, password):
        salt = b'salt_'  # In production, use a random salt and store it
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def encrypt(self):
        try:
            message = self.message_text.get("1.0", tk.END).strip()
            key = self.key_entry.get()
            method = self.method.get()
            
            if not message or not key:
                messagebox.showerror("Error", "Please enter both message and key/password")
                return
                
            if method == "caesar":
                result = self.caesar_cipher(message, key)
            elif method == "vigenere":
                result = self.vigenere_cipher(message, key)
            else:  # AES
                f = self.get_fernet_key(key)
                result = f.encrypt(message.encode()).decode()
                
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        try:
            message = self.message_text.get("1.0", tk.END).strip()
            key = self.key_entry.get()
            method = self.method.get()
            
            if not message or not key:
                messagebox.showerror("Error", "Please enter both message and key/password")
                return
                
            if method == "caesar":
                result = self.caesar_cipher(message, key, decrypt=True)
            elif method == "vigenere":
                result = self.vigenere_cipher(message, key, decrypt=True)
            else:  # AES
                f = self.get_fernet_key(key)
                result = f.decrypt(message.encode()).decode()
                
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = EncryptionTool()
    app.run()
