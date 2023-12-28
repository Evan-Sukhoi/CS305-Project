from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def encrypt_with_public_key(public_key, plaintext):
    public_key_obj = serialization.load_pem_public_key(public_key, backend=default_backend())
    ciphertext = public_key_obj.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_with_private_key(private_key, ciphertext):
    private_key_obj = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    plaintext = private_key_obj.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def symmetric_encrypt(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def symmetric_decrypt(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


# Server side
server_private_key, server_public_key = generate_keys()

# Client side
client_private_key, client_public_key = generate_keys()

# Client requests the public key of the server
# In a real-world scenario, this could be done over a secure channel
server_public_key_received = server_public_key

# Client generates a key for symmetric encryption
symmetric_key = os.urandom(32)

# Client uses the public key obtained from the server to encrypt the symmetric key
encrypted_symmetric_key = encrypt_with_public_key(server_public_key_received, symmetric_key)

# Client sends the encrypted symmetric key to the server
# In a real-world scenario, this communication should be secured (e.g., HTTPS)
# Also, you may want to add proper error handling in production code
server_decrypted_symmetric_key = decrypt_with_private_key(server_private_key, encrypted_symmetric_key)

# Now both server and client have the same symmetric key for further communication

# Example of symmetric encryption and decryption
message = b'Hello, secure world!'
encrypted_message = symmetric_encrypt(server_decrypted_symmetric_key, message)
decrypted_message = symmetric_decrypt(server_decrypted_symmetric_key, encrypted_message)

print(f"Original Message: {message}")
print(f"Encrypted Message: {base64.b64encode(encrypted_message)}")
print(f"Decrypted Message: {decrypted_message}")
