import os
import time
from cryptography.fernet import Fernet

# Chipper (Simetris - Fernet)
# =======================================

# Function to load Fernet key from file
def load_key(filename):
    with open(filename, "rb") as f:
        return f.read()

# Function to save Fernet key to file
def save_key(filename, key):
    with open(filename, "wb") as f:
        f.write(key)

# Decrypt data using Fernet key
def decrypt_with_key(encrypted_data, key):
    fernet_cipher = Fernet(key)
    decrypted_data = fernet_cipher.decrypt(encrypted_data)
    return decrypted_data

# Function to generate a new Fernet key
def generate_new_key(filename):
    print("Generating a new key...")
    new_fernet_key = Fernet.generate_key()
    save_key(filename, new_fernet_key)
    print("New key has been generated and saved.")

# File to store the Fernet key
key_file = "fernet_key.pem"

# Check if key file exists and load the key
try:
    fernet_key = load_key(key_file)
    if len(fernet_key) != 32:
        raise ValueError("Invalid key length")
    
except (FileNotFoundError, ValueError):
    # Generate Fernet key if the file doesn't exist or key is invalid
    fernet_key = Fernet.generate_key()
    save_key(key_file, fernet_key)

# Get the creation time of the key file
key_file_creation_time = os.path.getctime(key_file)

# Encrypt data using Fernet
data = b"Sensitive information"
fernet_cipher = Fernet(fernet_key)
encrypted_data = fernet_cipher.encrypt(data)
print("\nEncrypted data:", encrypted_data)

# Decrypt data using Fernet key read from file
decrypted_data = decrypt_with_key(encrypted_data, fernet_key)
print("Decrypted data:", decrypted_data.decode())

# Check if the key file creation time is greater than 1 minute
current_time = time.time()
time_difference = current_time - key_file_creation_time

if time_difference > 60:
    generate_new_key(key_file)


# RSA (Asimetris)
# =====================

import os.path
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    """Generate and save RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

def load_keys():
    """Load RSA key pair from files."""
    with open("public_key.pem", "rb") as public_key_file:
        public_key_pem = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

    with open("private_key.pem", "rb") as private_key_file:
        private_key_pem = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
            backend=default_backend()
        )

    return public_key_pem, private_key_pem

def encrypt_decrypt(public_key_pem, private_key_pem):
    """Encrypt and decrypt a message using RSA keys."""
    plaintext = b"Hello, this is a secret message!"

    encrypted = public_key_pem.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypted = private_key_pem.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\nOriginal plaintext:", plaintext.decode())
    print("Encrypted ciphertext:", encrypted.hex())
    print("Decrypted plaintext:", decrypted.decode())

def check_key_regeneration():
    """Check if RSA keys need to be regenerated based on creation time."""
    if os.path.exists("public_key.pem") and os.path.exists("private_key.pem"):
        current_time = time.time()
        public_key_creation_time = os.path.getctime("public_key.pem")
        private_key_creation_time = os.path.getctime("private_key.pem")
        if current_time - public_key_creation_time > 60 or current_time - private_key_creation_time > 60:
            print("Regenerating keys...")
            generate_keys()
    else:
        generate_keys()

check_key_regeneration()
public_key_pem, private_key_pem = load_keys()
encrypt_decrypt(public_key_pem, private_key_pem)


# Hashing (Bycrpt)
# =======================================
    
import bcrypt
import time
import os

# Function to generate hashed password
def generate_hashed_password():
    password = b"securepassword"
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    with open("hashed_password.pem", "wb") as file:
        file.write(hashed_password)
    print("\nHashed password saved to hashed_password.pem")

# Function to load hashed password
def load_hashed_password():
    with open("hashed_password.pem", "rb") as file:
        hashed_password = file.read()
    return hashed_password

# Function to check if password matches hashed value
def check_password(input_password, hashed_password):
    if bcrypt.checkpw(input_password, hashed_password):
        print("Password matches!")
    else:
        print("Password does not match!")

# Check if hashed password file exists
if not os.path.exists("hashed_password.pem"):
    generate_hashed_password()

# Load hashed password
hashed_password = load_hashed_password()

# Get creation time of hashed password file
creation_time = os.path.getctime("hashed_password.pem")
current_time = time.time()

# Check if it's time to generate new hashed password
if current_time - creation_time > 60:
    print("Generate new hashing..")
    generate_hashed_password()
    hashed_password = load_hashed_password()
    print("Hashing has been generated and saved")

# Check password
input_password = b"securepassword"
check_password(input_password, hashed_password)
