import string # used to grab al lthe lowercase, uppercase, special keys, and number values
import random 
import datetime

def GenPass(minLength, maxLength = None, numbers=True, specialCharacters=True): #Generate Password
    # if maxLength is provided and valid, choose a random length between minLength and maxLength
    if maxLength and maxLength > minLength:
        passwordLength = random.randint(minLength, maxLength)
    else:
        # if no max length is specified, the password will be at least minLength
        passwordLength = minLength

    #---------------------------#
    #make these all into a list that were going to choose from randomly 
    letters = string.ascii_letters
    digits = string.digits 
    special = string.punctuation 
    #--------------------------#
    characters = letters
    if numbers:
        characters += digits
    if specialCharacters:
        characters += special

    passwordList = ""
    correct = False
    numberQ = False
    specialQ = False

    while not correct or len(passwordList) < passwordLength:
        newChar = random.choice(characters)
        passwordList += newChar

        if newChar in digits:
            numberQ = True
        elif newChar in special:
            specialQ = True
        
        correct = True
        if numbers:
            correct = numberQ
        if specialCharacters:
            correct = correct and specialQ

    return passwordList

if __name__ == "__main__":
    minLength = int(input("ENTER A MINIMUM LENGTH: "))
    maxLength_input = input("ENTER A MAX LENGTH (or press 'return/enter' for no max): ")
    maxLength = int(maxLength_input) if maxLength_input else None
    numberQ = input("DO you want to have numbers (y/n): ").lower() == "y"
    specialQ = input("DO you want to have special Characters (y/n): ").lower() == "y"
    passwordList = GenPass(minLength, maxLength, numberQ, specialQ )
    print("Generated:",passwordList)
