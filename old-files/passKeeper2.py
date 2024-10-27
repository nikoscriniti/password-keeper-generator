import random
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

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

# Load or generate salt
def load_or_generate_salt(master_pwd):
    try:
        with open("passwords1.txt", "r") as f:
            for line in f:
                if line.startswith(f"Master:{master_pwd};"):
                    return base64.urlsafe_b64decode(line.split(";")[1])
        return None
    except FileNotFoundError:
        return None

def write_salt(master_pwd, salt):
    # Read the current contents of the file
    with open("passwords1.txt", "r") as f:
        lines = f.readlines()

    # Write back the contents, replacing the line for the master password if it exists
    with open("passwords1.txt", "w") as f:
        master_found = False
        for line in lines:
            if line.startswith(f"Master:{master_pwd};"):
                f.write(f"Master:{master_pwd};{base64.urlsafe_b64encode(salt).decode()}\n")
                master_found = True
            else:
                f.write(line)
        
        if not master_found:
            f.write(f"Master:{master_pwd};{base64.urlsafe_b64encode(salt).decode()}\n")

def get_key(master_pwd):
    salt = load_or_generate_salt(master_pwd)
    if salt is None:
        salt = os.urandom(16)
        write_salt(master_pwd, salt)
    return derive_key_from_password(master_pwd, salt)

def view(master_pwd):
    key = get_key(master_pwd)
    fer = Fernet(key)
    found = False
    try:
        with open("passwords1.txt", "r") as f:
            lines = f.readlines()
            inside_block = False
            for line in lines:
                if line.startswith(f"Master:{master_pwd};"):
                    inside_block = True
                    found = True
                    continue
                elif line.startswith("Master:") and inside_block:
                    inside_block = False
                    break
                elif inside_block:
                    try:
                        user, passw = line.rstrip().split(";")
                        print(f"User: {user} | Password: {fer.decrypt(passw.encode()).decode()}")
                    except Exception as e:
                        print("Error decrypting password:", e)
        if not found:
            print("No passwords found for this master password.")
    except FileNotFoundError:
        print("No passwords found.")

def add(master_pwd):
    key = get_key(master_pwd)
    fer = Fernet(key)
    
    name = input("Account: ")
    pwd = input("Password: ")
    encrypted_pwd = fer.encrypt(pwd.encode()).decode()
    
    with open("passwords1.txt", "r") as f:
        lines = f.readlines()

    with open("passwords1.txt", "w") as f:
        master_found = False
        for line in lines:
            if line.startswith(f"Master:{master_pwd};"):
                master_found = True
                f.write(line)  # Keep the existing line for this master password
            else:
                f.write(line)

        if master_found:
            f.write(f"{name};{encrypted_pwd}\n")
        else:
            f.write(f"Master:{master_pwd};{base64.urlsafe_b64encode(os.urandom(16)).decode()}\n")
            f.write(f"{name};{encrypted_pwd}\n")

if __name__ == "__main__": 
    while True:
        master_pwd = input("Enter your master password: ")

        mode = input("Would you like to add a new password or view old ones (view, add)? ")
        
        if mode == "q":
            break
        elif mode == "view":
            view(master_pwd)
        elif mode == "add":
            add(master_pwd)
        else:
            print("Invalid option.")