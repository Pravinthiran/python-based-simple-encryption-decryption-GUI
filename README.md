# Encryption/Decryption Tool

A user-friendly Python GUI application for encrypting and decrypting messages using three popular methods: Caesar Cipher, Vigenère Cipher, and AES (Fernet). This tool is perfect for learning about cryptography or securing your personal notes.

---

## 🚀 Features
- **Three encryption methods:**
  - Caesar Cipher (simple shift)
  - Vigenère Cipher (keyword-based)
  - AES (Fernet) for strong, modern encryption
- **Easy-to-use GUI** built with Tkinter
- **Instant encryption and decryption**
- **Copy-paste support** for messages and results
- **Error handling** and helpful messages

---

## 🛠️ Installation
1. **Clone or download** this repository to your computer.
2. Make sure you have **Python 3.7+** installed.
3. Install the required package:
   ```bash
   pip install cryptography
   ```

---

## 💻 Usage
1. Run the script:
   ```bash
   python "A Simple Encrytion Decryption Tool.py"
   ```
2. The GUI window will appear.

### 🖼️ GUI Overview
- **Encryption Method:** Select Caesar, Vigenère, or AES (Fernet).
- **Key/Password:** Enter the key (number for Caesar, word for Vigenère, password for AES).
- **Message:** Type or paste the message you want to encrypt or decrypt.
- **Encrypt/Decrypt Buttons:** Click to perform the action.
- **Result:** View the output below.

> **Note:** For AES, use a strong password. For Vigenère, use only alphabetic characters as the key.

---

## ✨ Example Scenarios

### Caesar Cipher
- **Key:** 3
- **Message:** Hello World
- **Encrypted:** Khoor Zruog

### Vigenère Cipher
- **Key:** KEY
- **Message:** Hello World
- **Encrypted:** Rijvs Uyvjn

### AES (Fernet)
- **Password:** mysecret123
- **Message:** Hello World
- **Encrypted:** (A long string like `gAAAAABk...`)

---

## 🧩 Troubleshooting
- **No GUI appears?**
  - Make sure you are running the script with Python 3.
  - Check if Tkinter is installed (it comes with most Python installations).
- **ModuleNotFoundError: cryptography?**
  - Run `pip install cryptography`.
- **Decryption fails?**
  - Ensure you use the same method and key/password as for encryption.
  - For AES, the password must match exactly.

---

## ❓ FAQ
**Q: Can I use this for files?**
- Not directly. This tool is for text messages only.

**Q: Is the encryption secure?**
- AES (Fernet) is secure for most personal uses. Caesar and Vigenère are for educational purposes only.

**Q: Can I use non-English characters?**
- Caesar and Vigenère work best with English letters. AES supports any text.

---

## 📸 Screenshots
> _You can add screenshots of the GUI here!_

---

## 📜 License
This project is licensed under the MIT License. 
