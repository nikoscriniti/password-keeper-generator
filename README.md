# PassKeeper

PassKeeper is a simple password management utility that allows you to securely store and retrieve passwords using encryption. This repository includes various scripts and keys necessary for encrypting and decrypting passwords.

## Files Overview

- **`encryption_utils.py`**  
  This file contains utility functions for encryption and decryption, such as:
  - Generating encryption keys.
  - Encrypting data (passwords).
  - Decrypting data using a specified key.
  - Handling various encryption-related operations.

- **`key.key`**  
  The generated encryption key used for encrypting and decrypting password data. This file should be kept secure, as losing it will result in an inability to decrypt stored passwords.

- **`master_key.key`**  
  Contains a master key for additional security measures, such as encrypting the primary encryption key (`key.key`). This adds a layer of protection by securing the key itself.

- **`passkeeper(main-file).py`**  
  The main script for the PassKeeper utility, which includes functionality for:
  - Adding a new password.
  - Retrieving existing passwords.
  - Encrypting and storing password data using `encryption_utils.py`.
  - Managing key usage for data protection.

## Prerequisites

- Python 3.x
- Required Python packages (possibly including `cryptography` for encryption)