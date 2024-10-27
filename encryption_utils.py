# helpful website: https://cryptography.io/en/latest/fernet/
'''orignially: store the master passwords with dictionaries and the master passwords is the key 
    then making the other information such as the account name and password a list/dictionary within the main dictionary
'''

import base64
import hashlib
''' ^^^ digest() method in Python's hashlib module finalizes the hashing process and returns the raw bytes of the hash value
        ^^^ it takes the data you provided (such as a password) and runs it through a cryptographic hash function (like SHA-256) to generate a fixed-length output
'''
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
''' ^^^ s a key derivation function (KDF) that securely generates cryptographic keys from passwords
     ^^^ it uses a combination of a password, a salt, and multiple iterations to produce a derived key
        ^^^ Key Derivation Function (KDF) is a cryptographic algorithm, generates a secure cryptographic key from a less secure input, like a password
'''
from cryptography.hazmat.primitives import hashes
''' ^^^  provides a variety of cryptographic hash functions like SHA-256, SHA-512
         ^^^ SHA-256 and SHA-512 are cryptographic hash functions, part of the SHA-2 (Secure Hash Algorithm 2) family... which take an input (like a password or file) and generate a fixed-length output, or "hash," that uniquely represents the input
                SHA-256: Produces a 256-bit (32-byte) hash
                SHA-512: Produces a 512-bit (64-byte) hash
'''
from cryptography.fernet import Fernet
''' ^^^ Fernet is a symmetric encryption system, meaning the same key is used to both encrypt and decrypt data
'''

# NOTES: the whole b" or b' is a byte string, what is happening is view/add is receving the regular string and making it a byte string
    # ^^ https://cryptography.io/en/latest/fernet/ have to add this

greek_map = {  # maps base64 characters to Greek letters for encoding.
    'A': 'α', 'B': 'β', 'C': 'γ', 'D': 'δ', 'E': 'ε', 'F': 'ζ', 'G': 'η', 'H': 'θ',
    'I': 'ι', 'J': 'κ', 'K': 'λ', 'L': 'μ', 'M': 'ν', 'N': 'ξ', 'O': 'ο', 'P': 'π',
    'Q': 'ρ', 'R': 'σ', 'S': 'τ', 'T': 'υ', 'U': 'φ', 'V': 'χ', 'W': 'ψ', 'X': 'ω',
    'Y': 'α', 'Z': 'β', 'a': 'γ', 'b': 'δ', 'c': 'ε', 'd': 'ζ', 'e': 'η', 'f': 'θ',
    'g': 'ι', 'h': 'κ', 'i': 'λ', 'j': 'μ', 'k': 'ν', 'l': 'ξ', 'm': 'ο', 'n': 'π',
    'o': 'ρ', 'p': 'σ', 'q': 'τ', 'r': 'υ', 's': 'φ', 't': 'χ', 'u': 'ψ', 'v': 'ω',
    'w': 'α', 'x': 'β', 'y': 'γ', 'z': 'δ',
    '0': 'ε', '1': 'ζ', '2': 'η', '3': 'θ', '4': 'ι', '5': 'κ', '6': 'λ', '7': 'μ', '8': 'ν', '9': 'ξ',
    '+': 'ο', '/': 'π', '=': 'ρ'
}

#--------------------#
'''maps Greek letters back to base64 characters for decoding'''
reverse_greek_map = {}
    # "o" represents the original base64 character, and "g" represents the corresponding Greek letter. (this will be reversed in line 27)
for o, g in greek_map.items(): # goes through each key-value pair in greek_map (dictionary)
    reverse_greek_map[g] = o 
#--------------------#

#------------------------------------#
'''the functions Go hand in hand (..made the same way just reveresed)'''
def base64_to_greek(base64_str): # function is taking the hashed/kinda-encrypted master password, and changing the letters to greek
    # create an empty string to hold the Greek letters
    greek_str = ""
    # Loop through each character in the base64 string
    for char in base64_str:
        # find the Greek letter for the current base64 character
        greek_char = greek_map.get(char, char) # if the character is not in the greek_map, use the character itself (to avoid eror with not having the chracter), char is the second option to just default 
        # add the Greek letter to the result string
        greek_str += greek_char
    return greek_str # return the string, this worked easier then storing it as a list 

def greek_to_base64(greek_str):
    base64_str = ""
    for char in greek_str:    # looping through each character in the Greek string
        base64_char = reverse_greek_map.get(char, char) # reverd greek map
        base64_str += base64_char #keep adding it string (just makes it harder to decode if someone tries)
    return base64_str
'''the functions Go hand in hand (..made the same way just reveresed)'''
#------------------------------------#


def hash_master_password(master_pwd): 
    hash_object = hashlib.sha256(master_pwd.encode()) # --->  ceates a SHA-256 hash object from the master password (converted to bytes)
    base64_hash = base64.b64encode(hash_object.digest()).decode()  # in Python this function that takes binary data (often represented as bytes) and encodes it into a base64-encoded string
        #^ hexdigest() gives  a hex-encoded string instead of raw bytes... digest() is necessary when working with the raw hash, especially for converting to base64
        #^ Calling digest() returns the raw binary hash value (a series of bytes) for that input data
        #^ No matter how long the input is, the output will always be the same fixed size (e.g., 32 bytes for SHA-256)
    return base64_to_greek(base64_hash) # now run this hash into the greek letter changer to get an even more secure structure

def derive_key_from_password(password, salt): # explained more in ---> https://cryptography.io/en/latest/fernet/
    kdf = PBKDF2HMAC( 
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode())) # needed straight from the website (https://cryptography.io/en/latest/fernet/)
    return key


#------------------------------------#
'''the functions Go hand in hand '''
def encrypt_master_password(master_pwd):
    return hash_master_password(master_pwd)
    
def decrypt_master_password(encrypted_pwd):
    base64_hash = greek_to_base64(encrypted_pwd)
    return base64_hash
'''the functions Go hand in hand '''
#------------------------------------#
