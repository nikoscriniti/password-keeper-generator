# main file
import os
import base64
from cryptography.fernet import Fernet
from encryption_utils import encrypt_master_password, decrypt_master_password, derive_key_from_password

def load_salt(encrypted_pwd):
    try:
        with open("passwords3.txt", "r") as f:
            for line in f:
                if line.startswith(f"Master:{encrypted_pwd};"):
                    return base64.urlsafe_b64decode(line.split(";")[1])
                        # a salt is a random value added to a password before hashing
                        # function takes the base64-encoded string (the second part of the split line) and decodes it back into its original binary form. This decoded binary data represents the salt used for password encryption
                        # line.split(";")[1] extracts the second part of the line, which is assumed to contain the base64-encoded salt
        return None # If any of these steps fails (e.g., due to file not found, incorrect pattern, or decoding error), the try block will raise an exception
    except FileNotFoundError:
        return None

def write_salt(encrypted_pwd, salt): # important in terms of the "salt"
    '''1: encrypted_pwd  this is the master password that has already been encrypted (or hashed)
       2: salt this is a random value used during password hashing to make the resulting hash unique, even if two users have the same password '''
    with open("passwords3.txt", "a") as f:
        f.write(f"Master:{encrypted_pwd};{base64.urlsafe_b64encode(salt).decode()}\n")
            # ^^ 1. passwords3.txt file in append mode (so no existing data is lost) 
            # ^^ 2. writes a new line in the format "Master:encrypted_master_password;sal" to the file (visable in the actual passwords (check this))
            # ^^ 3. the salt is encoded using base64 to make it safe for storage as a string
            # ^^ 4. base64.urlsafe_b64encode(salt) converts the binary salt to a base64 encoded string
            # ^^ 5. decode() converts the base64 encoded bytes to a regular string


def get_key(master_pwd): # this is the plain text input value the user gives (very important)
    encrypted_pwd = encrypt_master_password(master_pwd) 
    salt = load_salt(encrypted_pwd) # now salt is the encrpytion password, just hashed again
    if salt is None: # their already might be a salt (meaning all ready a masterpassword)
        salt = os.urandom(16)
        write_salt(encrypted_pwd, salt)
    return derive_key_from_password(encrypted_pwd, salt) # Use the encrypted master password and the salt to derive a cryptographic key, (all code from the resource)

def view(master_pwd):
    key = get_key(master_pwd)
    fer = Fernet(key)
    encrypted_pwd = encrypt_master_password(master_pwd)
    found = False
    try:
        with open("passwords3.txt", "r") as f:
            lines = f.readlines()
            inside_block = False # this is the inside information within each master password ---> bascially the master passowrd acts a key in a dictionary and then a list (account info and passowrds) is stored as the value 
            for line in lines:
                if line.startswith(f"Master:{encrypted_pwd};"):
                    inside_block = True
                    continue  # skips asking the master password line
                elif line.startswith("Master:") and inside_block:
                    inside_block = False  # End of this master password block
                    # print("No passwords found for this master password.")
                    break
                      # Exit loop since we finished this block
                elif inside_block:
                    parts = line.rstrip().split(";")
                    if len(parts) == 3:  # Ensure there are exactly 3 parts
                        _, user, passw = parts
                        try:
                            print(f"User: {user} | Password: {fer.decrypt(passw.encode()).decode()}")
                            found = True # ADDED ---> so it will default go to lines ---> "if not found:"
                        except Exception as e:
                            print("Error decrypting password:", e)
        if not found: # change this (remove the not), then "no passwords..." will show, but it will save that as an actual passowrd so it comes up later in view
            print("No passwords found for this master password.")
    except FileNotFoundError:
        print("No passwords found.")
    #if not found:
        #print("No passwords found for this master password.")


def add(master_pwd):
    key = get_key(master_pwd)
    fer = Fernet(key)
    encrypted_pwd = encrypt_master_password(master_pwd)
    
    name = input("Account: ")
    pwd = input("Password: ")
    encrypted_password = fer.encrypt(pwd.encode()).decode()
    
    with open("passwords3.txt", "a") as f:
        f.write(f"{encrypted_pwd};{name};{encrypted_password}\n")

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