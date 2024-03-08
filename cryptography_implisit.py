from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import bcrypt

# Fernet (Simetris)
# =====================

# Generate Fernet key
fernet_key = Fernet.generate_key()
fernet_cipher = Fernet(fernet_key)

# Encrypt data using Fernet
data = b"Sensitive information"
encrypted_data = fernet_cipher.encrypt(data)
print("\nEncrypted data:", encrypted_data)

# Decrypt data using Fernet
decrypted_data = fernet_cipher.decrypt(encrypted_data)
print("Decrypted data:", decrypted_data.decode())


# RSA Encryption/Decryption (Asimetris)
# =====================

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize the public key
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

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


# Hashing
# =====================

# Hash a password using bcrypt
password = b"securepassword"
hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
print("\nHashed password:", hashed_password)

# Check if a password matches hashed value
input_password = b"securepassword"
if bcrypt.checkpw(input_password, hashed_password):
    print("Password matches!")
else:
    print("Password does not match!")
