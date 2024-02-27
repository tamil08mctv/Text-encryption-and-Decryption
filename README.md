# Text-encryption-and-Decryption
The text can be encrpyted and decrpyted
Text Encryption and Decryption Tool

This tool allows you to encrypt and decrypt text files using a password-based encryption algorithm.

## Requirements

- Python 3.x
- `cryptography` library (install via `pip install cryptography`)

## Usage

1. **Encryption:**

    To encrypt a text file, follow these steps:

    - Run the `encrypt_text.py` script.
    - Enter the path to the text file you want to encrypt.
    - Enter a password to lock the file.
    - Confirm the password.
    - The encrypted file will be created in the same directory as the original file with the `.enc` extension.

2. **Decryption:**

    To decrypt an encrypted text file, follow these steps:

    - Run the `decrypt_text.py` script.
    - Enter the path to the encrypted text file you want to decrypt.
    - Enter the password used to encrypt the file.
    - The decrypted file will be created in the same directory as the encrypted file with the `.dec` extension.
