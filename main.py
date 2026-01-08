import os
import base64
from datetime import datetime
from getpass import getpass
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ===================== REQUIRED DEFAULTS (FIX) =====================
# The core uses key_file_name as a default argument, so it MUST exist before the class is defined.
KEY_FILE_DEFAULT = "my_secret.key"
key_file_name = KEY_FILE_DEFAULT


# ===================== UI PRINT =====================
def c_print(msg_type, message):
    types = {
        "error":   ("\033[1;31m", "ERROR"),
        "success": ("\033[1;32m", "SUCCESS"),
        "notice":  ("\033[1;36m", "NOTICE"),
        "info":    ("\033[1;34m", "INFO"),
        "input":   ("\033[1;35m", "INPUT"),
        "warning": ("\033[1;33m", "WARNING"),
        "other":   ("\033[1;36m", "*")
    }
    reset = "\033[0m"
    color, label = types.get(msg_type.lower(), ("\033[1;37m", "INFO"))
    print(f"{color}[{label}]{reset} {message}")


# ===================== CORE (UNCHANGED) =====================
class CryptoTool:
    def __init__(self):
        self.key = None

    def generate_key(self, key_name=key_file_name):
        self.key = Fernet.generate_key()
        with open(key_name, "wb") as key_file:
            key_file.write(self.key)
        c_print("success", f"Random key generated and saved to '{key_name}'")

    def load_key(self, key_name=key_file_name):
        try:
            with open(key_name, "rb") as key_file:
                self.key = key_file.read()
            c_print("notice", "Start generating secret key file ... ")
            c_print("success", f"Key file loaded successfully in ./{key_name}")
        except FileNotFoundError:
            c_print("error", f"Key file '{key_name}' not found")

    def set_key_from_password(self, password):
        salt = b'static_salt_value_123'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        c_print("success", "Key generated from password")

    def encrypt_file(self, filename):
        if not self.key:
            c_print("error", "No key loaded")
            return
        try:
            with open(filename, "rb") as f:
                data = f.read()
            encrypted = Fernet(self.key).encrypt(data)
            with open(filename + ".encrypted", "wb") as f:
                f.write(encrypted)
            c_print("success", f"File encrypted: ./{filename}.encrypted")
        except Exception as e:
            c_print("error", f"Encryption failed: {e}")

    def decrypt_file(self, filename):
        if not self.key:
            c_print("error", "No key loaded")
            return
        try:
            with open(filename, "rb") as f:
                data = f.read()
            decrypted = Fernet(self.key).decrypt(data)
            original = filename.replace(".encrypted", "")
            with open(original, "wb") as f:
                f.write(decrypted)
            c_print("success", f"File decrypted: {original}")
        except Exception:
            c_print("error", "Decryption failed (wrong key or password)")


# ===================== SAFE INPUT HELPERS =====================
def ask_choice(prompt, valid):
    valid_set = set(valid)
    while True:
        val = input(prompt).strip()
        if val in valid_set:
            return val
        c_print("warning", f"Invalid choice ({'/'.join(valid)})")

def ask_text(prompt):
    while True:
        val = input(prompt).strip()
        if val:
            return val
        c_print("warning", "Input cannot be empty")

def ask_text_default(prompt, default_value):
    val = input(prompt).strip()
    return val if val else default_value

def ask_yes_no(prompt):
    choice = ask_choice(prompt, ["y", "Y", "n", "N"])
    return choice.lower() == "y"

def normalize_file_path(raw_path):
    p = Path(raw_path).expanduser()
    # Keep relative paths relative to current working directory for nicer UX.
    return p

def ensure_real_file(path_obj):
    if not path_obj.exists():
        c_print("error", f"File not found: {path_obj.resolve()}")
        return False
    if path_obj.is_dir():
        c_print("error", f"That is a directory, not a file: {path_obj.resolve()}")
        return False
    return True

def ask_file(prompt, act_file):
    while True:
        raw = ask_text(prompt)
        p = normalize_file_path(raw)

        if ensure_real_file(p):
            if act_file == "1":
                c_print("notice", f"Chosen file to Encrypt set to {p.resolve()}")
            else:
                c_print("notice", f"Chosen file to Decrypt set to {p.resolve()}")
            return str(p)
        # ensure_real_file already prints the reason


# ===================== UI FLOW =====================
def banner():
    c_print("other", "   Tool o safi   ")

def setup_key(tool: CryptoTool):
    c_print("info", "Key mode:")
    c_print("other", "(1) Random key file (highest security)")
    c_print("other", "(2) Password-based key")
    choice = ask_choice("\033[1;35m[INPUT]\033[0m You're choose: ", ["1", "2"])

    if choice == "1":
        key_path_str = ask_text_default(
            f"\033[1;35m[INPUT]\033[0m Enter path to store/load key file (Default: ./{KEY_FILE_DEFAULT}): ",
            KEY_FILE_DEFAULT
        )
        key_path = normalize_file_path(key_path_str)

        # If they typed a directory, place the key file inside it.
        if key_path.exists() and key_path.is_dir():
            key_path = key_path / KEY_FILE_DEFAULT

        # Make sure parent directories exist if user typed e.g. keys/my.key
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            tool.load_key(str(key_path))
        else:
            c_print("notice", "Key not found, generating new one")
            tool.generate_key(str(key_path))

    else:
        # Hide password input in terminal (safer than input()).
        while True:
            pwd = getpass("\033[1;35m[INPUT]\033[0m Enter password: ")
            confirm = getpass("\033[1;35m[INPUT]\033[0m  Confirm password: ")
            if pwd and pwd == confirm:
                break
            c_print("warning", "Passwords do not match (or empty). Try again.")

        tool.set_key_from_password(pwd)

def actions(tool: CryptoTool):
    while True:
        c_print("info", "Encrypt or Decrypt")
        c_print("other", "(1) Encrypt file")
        c_print("other", "(2) Decrypt file")
        c_print("other", "(X) Exit")
        act = ask_choice("\033[1;35m[INPUT]\033[0m You're choose: ", ["1", "2", "X", "x"])

        if act in ("X", "x"):
            c_print("notice", "Exiting. Stay safe.")
            break

        if act == "1":
            file_path = ask_file("\033[1;35m[INPUT]\033[0m Enter file path to Encrypt: ", act)

            if file_path.endswith(".encrypted"):
                c_print("warning", "This file already looks encrypted (*.encrypted). Skipping to avoid double-encryption.")
                continue

            tool.encrypt_file(file_path)

        else:
            file_path = ask_file("\033[1;35m[INPUT]\033[0m Enter file path to Decrypt: ", act)

            if not file_path.endswith(".encrypted"):
                if not ask_yes_no("File does not end with .encrypted. Try decrypt anyway? (y/n): "):
                    continue

            out_path = file_path.replace(".encrypted", "")
            out_p = Path(out_path)

            if out_p.exists():
                if not ask_yes_no(f"\033[1;35m[INPUT]\033[0m Output file '{out_p.name}' already exists. Overwrite? (y/n): "):
                    c_print("notice", "Decryption cancelled to avoid overwrite.")
                    continue

            tool.decrypt_file(file_path)


# ===================== ENTRY POINT =====================
if __name__ == "__main__":
    banner()
    tool = CryptoTool()
    setup_key(tool)
    actions(tool)
