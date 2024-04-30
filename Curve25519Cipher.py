import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

class Curve25519Crypt:
    def __init__(self, filename, user_key):
        self.filename = filename
        self.user_key = user_key.encode()  # Encoding the user key to bytes

    def derive_key(self):
        # Hashing the user key to derive a symmetric key
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.user_key)
        return digest.finalize()

    def encrypt_file(self):
        if not os.path.exists(self.filename):
            raise FileNotFoundError("The specified file does not exist.")

        with open(self.filename, 'rb') as file:
            data = file.read()

        # Generate a private key for the encryption
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Deriving a symmetric key from the hashed user key
        symmetric_key = self.derive_key()

        # Encrypting the data
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted file
        encrypted_filename = self.filename + ".enc"
        with open(encrypted_filename, 'wb') as file:
            file.write(iv + encrypted_data)

        # Remove the original file
        os.remove(self.filename)

    def decrypt_file(self):
        encrypted_filename = self.filename + ".enc"
        if not os.path.exists(encrypted_filename):
            raise FileNotFoundError("The encrypted file does not exist.")

        with open(encrypted_filename, 'rb') as file:
            iv = file.read(16)
            encrypted_data = file.read()

        # Deriving the symmetric key from the hashed user key
        symmetric_key = self.derive_key()

        # Decrypting the data
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        # Save the decrypted file
        with open(self.filename, 'wb') as file:
            file.write(data)

        # Remove the encrypted file
        os.remove(encrypted_filename)

# Example usage (comment out these lines when testing or deploying in production)
# crypt = Curve25519Crypt('example.txt', 'my_secret_key')
# crypt.encrypt_file()
# crypt.decrypt_file()
