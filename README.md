
# Password Manager

A simple Python-based password manager that securely stores and retrieves passwords using encryption. The app uses SQLite for database management and AES encryption with PBKDF2 key derivation to keep your passwords safe.

## Features

- **Store Passwords Securely**: Passwords are encrypted using AES encryption.
- **Key Derivation**: A master password is used to generate a key using PBKDF2 with SHA256.
- **SQLite Database**: Stores passwords, usernames, and associated websites in a local SQLite database.
- **Retrieve Passwords**: Safely retrieve encrypted passwords for any website and username pair.

## Requirements

- Python 3.x
- `cryptography` library
- `sqlite3` (comes with Python by default)

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/m1sha1107/Password-Manager.git
   ```

2. **Install dependencies**:

   If you don't have the `cryptography` library installed, you can install it using pip:

   ```bash
   pip install cryptography
   ```

3. **Run the application**:

   In the project directory, run the Python script:

   ```bash
   python password_manager.py
   ```

## Usage

1. **Set up the database**: When you first run the app, the SQLite database will be created automatically.
2. **Enter the master password**: You will be prompted to enter a master password that will be used to derive an encryption key.
3. **Add a password**:
   - Choose option `1` to add a new password entry.
   - Enter the website name, username, and password.
4. **Retrieve a password**:
   - Choose option `2` to retrieve a password.
   - Enter the website name and username, and the app will decrypt and display the password.
5. **Exit**: Choose option `3` to exit the application.

## Security Notes

- The master password is used to derive a key that is used to encrypt and decrypt passwords. This key is never stored in the database.
- The encryption uses AES in CBC mode, which is a secure method for data encryption.
- The salt used for key derivation is fixed in this example. For better security, consider generating a unique salt for each user.
