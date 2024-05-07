from cryptography.fernet import Fernet
from argon2 import PasswordHasher, exceptions
import json
import getpass
import secrets


# Function to generate a Fernet key from master password
def generate_fernet_key():
    return Fernet.generate_key()


# Function to generate a salt for password hashing
def generate_salt():
    return secrets.token_bytes(16)  # 16 bytes = 128 bits


# Function to derive a key from the master password using Argon2
def derive_key(master_password, salt):
    ph = PasswordHasher()
    return ph.hash(master_password, salt)


# Function to encrypt passwords
def encrypt_passwords(passwords, key):
    cipher_suite = Fernet(key)
    encrypted_passwords = {}
    for acc, pwd in passwords.items():
        encrypted_passwords[acc] = cipher_suite.encrypt(pwd.encode()).decode()
    return encrypted_passwords


# Function to decrypt passwords
def decrypt_passwords(encrypted_passwords, key):
    cipher_suite = Fernet(key)
    passwords = {}
    for acc, enc_pwd in encrypted_passwords.items():
        passwords[acc] = cipher_suite.decrypt(enc_pwd.encode()).decode()
    return passwords


# Function to save passwords to a file
def save_passwords(passwords, key):
    encrypted_passwords = encrypt_passwords(passwords, key)
    with open('passwords.json', 'w') as f:
        json.dump(encrypted_passwords, f)


# Function to load passwords from a file
def load_passwords(key):
    try:
        with open('passwords.json', 'r') as f:
            encrypted_passwords = json.load(f)
            return decrypt_passwords(encrypted_passwords, key)
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        return {}


# Main function to manage passwords
def main() -> object:
    ph = PasswordHasher()
    while True:
        master_password = getpass.getpass("Enter your master password: ")
        try:
            with open('salt.txt', 'rb') as f:
                salt = f.read()
            key = derive_key(master_password, salt)
            if ph.verify(key, master_password):
                print("Login successful!")
                break
            else:
                print("Incorrect master password!")
        except FileNotFoundError:
            print("No master password found. Creating a new one...")
            salt = generate_salt()
            with open('salt.txt', 'wb') as f:
                f.write(salt)
            key = derive_key(master_password, salt)
            print("Master password created successfully!")

    fernet_key = generate_fernet_key()
    passwords = load_passwords(fernet_key)
    while True:
        print("\n1. Add a new password")
        print("2. Retrieve a password")
        print("3. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            account = input("Enter account name: ")
            password = getpass.getpass("Enter password: ")
            passwords[account] = password
            save_passwords(passwords, fernet_key)
            print("Password added successfully!")
        elif choice == '2':
            account = input("Enter account name: ")
            if account in passwords:
                print(f"Password for {account}: {passwords[account]}")
            else:
                print("Account not found!")
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
