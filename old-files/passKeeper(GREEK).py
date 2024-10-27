import random
import base64
import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Greek letter mapping for base64 characters (lowercase Greek letters)
greek_map = {
    'A': 'α', 'B': 'β', 'C': 'γ', 'D': 'δ', 'E': 'ε', 'F': 'ζ', 'G': 'η', 'H': 'θ',
    'I': 'ι', 'J': 'κ', 'K': 'λ', 'L': 'μ', 'M': 'ν', 'N': 'ξ', 'O': 'ο', 'P': 'π',
    'Q': 'ρ', 'R': 'σ', 'S': 'τ', 'T': 'υ', 'U': 'φ', 'V': 'χ', 'W': 'ψ', 'X': 'ω',
    'Y': 'α', 'Z': 'β', 'a': 'γ', 'b': 'δ', 'c': 'ε', 'd': 'ζ', 'e': 'η', 'f': 'θ',
    'g': 'ι', 'h': 'κ', 'i': 'λ', 'j': 'μ', 'k': 'ν', 'l': 'ξ', 'm': 'ο', 'n': 'π',
    'o': 'ρ', 'p': 'σ', 'q': 'τ', 'r': 'υ', 's': 'φ', 't': 'χ', 'u': 'ψ', 'v': 'ω',
    'w': 'α', 'x': 'β', 'y': 'γ', 'z': 'δ', '0': 'ε', '1': 'ζ', '2': 'η', '3': 'θ',
    '4': 'ι', '5': 'κ', '6': 'λ', '7': 'μ', '8': 'ν', '9': 'ξ', '+': 'ο', '/': 'π', '=': 'ρ'
}

# Reverse Greek map for decryption
reverse_greek_map = {v: k for k, v in greek_map.items()}

# Convert base64 string to Greek letters
def base64_to_greek(base64_str):
    return ''.join(greek_map.get(char, char) for char in base64_str)

# Convert Greek letters back to base64
def greek_to_base64(greek_str):
    return ''.join(reverse_greek_map.get(char, char) for char in greek_str)

# Function to hash and convert master password to Greek letters
def encrypt_master_password(master_pwd):
    hash_object = hashlib.sha256(master_pwd.encode())
    base64_hash = base64.b64encode(hash_object.digest()).decode()  # Hash the master password and convert to base64
    return base64_to_greek(base64_hash)  # Convert base64 to Greek letters

# Convert Greek back to base64, for comparison
def decrypt_master_password(greek_pwd):
    base64_hash = greek_to_base64(greek_pwd)
    return base64_hash

# Key derivation function using the master password and salt
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def load_key():
    try:
        with open("key.key", "rb") as key_file:
            salt = key_file.read(16)
        return salt
    except FileNotFoundError:
        return None

def write_key(salt):
    with open("key.key", "wb") as key_file:
        key_file.write(salt)

master_pwd = input("What is the master password: ")
salt = load_key()
if salt is None:
    salt = os.urandom(16)
    write_key(salt)
key = derive_key_from_password(master_pwd, salt)
fer = Fernet(key)

def view():
    try:
        with open("passwords2.txt", 'r') as f:
            for line in f.readlines():
                name, encrypted_pwd, greek_master_pwd = line.rstrip().split(";")
                if encrypted_pwd:  # Only process if there's a password to decrypt
                    print(f"Account: {name}\nPassword: {fer.decrypt(encrypted_pwd.encode()).decode()}")
                if greek_master_pwd:  # Only process if there's a Greek master password
                    print(f"Greek Master Password: {greek_master_pwd}")
    except FileNotFoundError:
        print("No passwords found.")

def add():
    name = input("Account: ")
    pwd = input("Password: ")
    encrypted_pwd = fer.encrypt(pwd.encode()).decode()
    greek_master_pwd = encrypt_master_password(master_pwd)  # Encrypt the master password to Greek letters
    with open('passwords2.txt', 'a') as f:
        f.write(f"{name};{encrypted_pwd};{greek_master_pwd}\n")

while True:
    mode = input("Would you like to add a new password or view old ones(view, add)? ")
    if mode == "q":
        break
    if mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid")