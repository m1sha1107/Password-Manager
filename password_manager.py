import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

# Database setup (SQLite)
DB_NAME = 'password_manager.db'  # Your database file

# Create a connection and cursor to interact with the SQLite database
def create_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        website TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password BLOB NOT NULL
                    )''')
    conn.commit()
    conn.close()

# Generate encryption key from master password using PBKDF2 (Key Derivation Function)
def generate_key(master_password: str):
    salt = b'some_random_salt'  # Ideally, use a unique salt per user
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=salt, 
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# Encrypt a password using AES
def encrypt_password(password: str, key: bytes):
    iv = os.urandom(16)  # Initialization vector for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_password = password + (16 - len(password) % 16) * ' '  # Padding to block size
    encrypted_password = encryptor.update(padded_password.encode()) + encryptor.finalize()
    return iv + encrypted_password

# Decrypt the password
def decrypt_password(encrypted_password: bytes, key: bytes):
    iv = encrypted_password[:16]  # Extract the IV (first 16 bytes)
    encrypted_data = encrypted_password[16:]  # The actual encrypted password
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_password.decode().strip()

# Add password to the database
def add_password(website: str, username: str, password: str, key: bytes):
    encrypted_password = encrypt_password(password, key)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)", 
                   (website, username, encrypted_password))
    conn.commit()
    conn.close()

# Retrieve password from the database
def get_password(website: str, username: str, key: bytes):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM passwords WHERE website = ? AND username = ?", 
                   (website, username))
    result = cursor.fetchone()
    conn.close()
    if result:
        encrypted_password = result[0]
        return decrypt_password(encrypted_password, key)
    return None

# Main logic for the password manager
def main():
    create_db()  # Ensure the DB is set up
    
    master_password = input("Enter your master password: ")
    key = generate_key(master_password)  # Derive key from the master password
    
    while True:
        print("\nPassword Manager")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            website = input("Enter website name: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            add_password(website, username, password, key)
            print("Password added successfully.")
        
        elif choice == '2':
            website = input("Enter website name: ")
            username = input("Enter username: ")
            retrieved_password = get_password(website, username, key)
            if retrieved_password:
                print(f"Password for {website}: {retrieved_password}")
            else:
                print("No password found for this website/username.")
        
        elif choice == '3':
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
