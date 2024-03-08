# import os
# import time
# from cryptography.fernet import Fernet

# # Chipper (Simetris - Fernet)
# # =======================================

# # Function to load Fernet key from file
# def load_key(filename):
#     with open(filename, "rb") as f:
#         return f.read()

# # Function to save Fernet key to file
# def save_key(filename, key):
#     with open(filename, "wb") as f:
#         f.write(key)

# # Decrypt data using Fernet key
# def decrypt_with_key(encrypted_data, key):
#     fernet_cipher = Fernet(key)
#     decrypted_data = fernet_cipher.decrypt(encrypted_data)
#     return decrypted_data

# # Function to generate a new Fernet key
# def generate_new_key(filename):
#     print("Generating a new key...")
#     new_fernet_key = Fernet.generate_key()
#     save_key(filename, new_fernet_key)
#     print("New key has been generated and saved.")

# # File to store the Fernet key
# key_file = "fernet_key.pem"

# # Check if key file exists and load the key
# try:
#     fernet_key = load_key(key_file)
#     if len(fernet_key) != 32:
#         raise ValueError("Invalid key length")
    
# except (FileNotFoundError, ValueError):
#     # Generate Fernet key if the file doesn't exist or key is invalid
#     fernet_key = Fernet.generate_key()
#     save_key(key_file, fernet_key)

# # Get the creation time of the key file
# key_file_creation_time = os.path.getctime(key_file)

# # Encrypt data using Fernet
# data = b"Sensitive information"
# fernet_cipher = Fernet(fernet_key)
# encrypted_data = fernet_cipher.encrypt(data)
# print("\nEncrypted data:", encrypted_data)

# # Decrypt data using Fernet key read from file
# decrypted_data = decrypt_with_key(encrypted_data, fernet_key)
# print("Decrypted data:", decrypted_data.decode())

# # Check if the key file creation time is greater than 1 minute
# current_time = time.time()
# time_difference = current_time - key_file_creation_time

# if time_difference > 60:
#     generate_new_key(key_file)


# RSA (Asimetris) NOT DONE YET!!!
# =====================

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os.path
import time

# Fungsi untuk memeriksa waktu pembuatan file
def is_key_old(filepath):
    current_time = time.time()
    file_time = os.path.getctime(filepath)
    return current_time - file_time > 60

# Fungsi untuk membuat kunci RSA dan menyimpannya dalam file .pem
def generate_and_save_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)

    with open("public_key.pem", "wb") as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)

# Fungsi untuk membaca kunci dari file .pem
def load_key(filepath):
    with open(filepath, "rb") as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return key

# Generate or load key
if not os.path.exists("private_key.pem") or is_key_old("private_key.pem"):
    generate_and_save_key()

private_key = load_key("private_key.pem")
public_key = load_key("public_key.pem")

# Data to be encrypted
data = b"Hello, this is a test message."

# Encrypt data using RSA public key
encrypted_rsa = public_key.encrypt(
    data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("\nEncrypted data with RSA:", encrypted_rsa)

# Decrypt data using RSA private key
decrypted_rsa = private_key.decrypt(
    encrypted_rsa,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Decrypted data with RSA:", decrypted_rsa.decode())


# # Hashing (Bycrpt)
# # =======================================
    
# import bcrypt
# import time
# import os

# # Function to generate hashed password
# def generate_hashed_password():
#     password = b"securepassword"
#     hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
#     with open("hashed_password.pem", "wb") as file:
#         file.write(hashed_password)
#     print("\nHashed password saved to hashed_password.pem")

# # Function to load hashed password
# def load_hashed_password():
#     with open("hashed_password.pem", "rb") as file:
#         hashed_password = file.read()
#     return hashed_password

# # Function to check if password matches hashed value
# def check_password(input_password, hashed_password):
#     if bcrypt.checkpw(input_password, hashed_password):
#         print("Password matches!")
#     else:
#         print("Password does not match!")

# # Check if hashed password file exists
# if not os.path.exists("hashed_password.pem"):
#     generate_hashed_password()

# # Load hashed password
# hashed_password = load_hashed_password()

# # Get creation time of hashed password file
# creation_time = os.path.getctime("hashed_password.pem")
# current_time = time.time()

# # Check if it's time to generate new hashed password
# if current_time - creation_time > 60:
#     print("Generate new hashing..")
#     generate_hashed_password()
#     hashed_password = load_hashed_password()
#     print("Hashing has been generated and saved")

# # Check password
# input_password = b"securepassword"
# check_password(input_password, hashed_password)
