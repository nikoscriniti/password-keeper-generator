#Password Keeer
 # ---> storing encrypting information and reading non-encrpted inforamtion
import random
import base64
import os
from cryptography.fernet import Fernet #module that comes allows the encryption process
# encrpyts text for you (I will use this, and encryt the text more, basically encrypting encrypted text)
# NOTES: the whole b" or b' is a byte string, what is happening is view/add is receving the regular string and making it a byte string
    # ^^ https://cryptography.io/en/latest/fernet/ have to add this
#-----#
# come in handy for the master password implementation
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
#-----#

'''
-----> allows for getting the key for encryption
def write_key(): # when this function is ran, it will create the key file 
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file: # wb is the write bits mode
        key_file.write(key) 

write_key()
'''

def derive_key_from_password(password, salt): # has to be written above the other
    kdf = PBKDF2HMAC( # read about what this function does ---->  key derivation function that securely derives a cryptographic key from a password using a salt and a hash function (like HMAC-SHA256)
                    #^^ the salt is random data added to a password before hashing to mak sure that identical passwords result in different hash values, preventing attackers from using precomputed tables (rainbow tables) to crack password
       algorithm = hashes.SHA256(),
        length =32,
        salt=salt,
        iterations=480000  # High iteration count for stronger key derivation
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))  # Encode key for Fernet
    return key

def load_key(): # write
    try:
        with open("key.key", "rb") as key_file: # rb is read bytes ( so itll read it in bytpes)
            salt = key_file.read(16)  # First 16 bytes are the salt
        return salt
    except FileNotFoundError: # there will never be filenotfounderror because i will always mainly write the key in already
        return None
    
def write_key(salt):
    with open("key.key", "wb") as key_file:
        key_file.write(salt)  # save the salt for future key derivation


master_pwd = input("Waht is the master password: ") # main password to unlock the rest 
salt = load_key() #assigning the value returned by the load_key() function (which reads the encryption key from a file) to the variable salt.
if salt is None:  # Generate new salt if it doesn't exist
    salt = os.urandom(16) # generates a random sequence of 16 bytes, which is used as the salt 
    write_key(salt)
 # ^^^ this will work with the encryption key
key = derive_key_from_password(master_pwd, salt) # run with the password of master password and, the salt value (with is the encrtpyion )
fer = Fernet(key)



def view(): # allow to view all the passwords
    try:
        with open("passwords.txt", 'r') as f:
            for line in f.readlines():
                user, passw = line.rstrip().split(";")
                print(f"User: {user}\nPassword: {fer.decrypt(passw.encode()).decode()}")
    except FileNotFoundError: # file will always exist (kinda dont need this)
        print("No passwords found.")
            # seperate the user from the password 
            #---------#


def add():
    name = input("Account:")
    pwd = input("Password:")
    encrypted_pwd = fer.encrypt(pwd.encode()).decode()  # encrypt the password, #decode it to a regular string takes in the byte string and decodes # first encoding the passwrod takes the string and converts it into bytes # fer. is converting the password into its encrypted version # file is named f, then writing in the following stuff into the file
    with open('passwords.txt', 'a') as f: # a mode (w, r, a) --> (w will create, or overide the file (clear the file completely and right over it)), (r will read, cant write), (a mode is append, add somethign to the end of the file and create a new file if fiel alredy exists) 
        f.write(f"{name};{encrypted_pwd}\n") # skip the line so you can keep writing them in 

while True:
    mode = input("Would you like to add a new password or view old ones(view, add)? ")# what mode user wants to go in

    if mode == "q":
        break # break the while loop 
    if mode == "view": # if q is true, it wont go through the if statments on this line and below
        view() 
    elif mode == "add":
        add()
    else:
        print("invalid")
        