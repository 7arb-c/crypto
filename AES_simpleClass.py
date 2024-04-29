import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

class AESCipher:
    def __init__(self, file_name, key):
        self.file_name = file_name
        self.key = self._hash_key(key)

    def _hash_key(self, key):
        # Hash the key using SHA-256 to generate a 32-byte key
        hashed_key = hashlib.sha256(key.encode()).digest()
        return hashed_key

    def encrypt(self):
        # Read the plaintext from the file
        with open(self.file_name, 'rb') as f:
            plaintext = f.read()

        # Create AES cipher object with the hashed key
        cipher = AES.new(self.key, AES.MODE_CBC)

        # Pad the plaintext to be a multiple of 16 bytes
        padded_plaintext = pad(plaintext, AES.block_size)

        # Encrypt the plaintext
        ciphertext = cipher.encrypt(padded_plaintext)

        # Write the ciphertext to a new file
        with open(self.file_name + '.enc', 'wb') as f:
            f.write(cipher.iv)
            f.write(ciphertext)

    def decrypt(self):
        # Read the initialization vector and ciphertext from the file
        with open(self.file_name, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()

        # Create AES cipher object with the hashed key and the initialization vector
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Decrypt the ciphertext
        decrypted_data = cipher.decrypt(ciphertext)

        # Unpad the decrypted data
        unpadded_data = unpad(decrypted_data, AES.block_size)

        # Write the decrypted plaintext to a new file
        with open(os.path.splitext(self.file_name)[0] + '_decrypted.txt', 'wb') as f:
            f.write(unpadded_data)

# Example usage:
file_name = input("Enter the name of the file to encrypt: ")
key = input("Enter the encryption key: ")
cipher = AESCipher(file_name, key)
cipher.encrypt()
print("File encrypted successfully.")

# To decrypt:
# decrypted_file_name = input("Enter the name of the file to decrypt: ")
# key = input("Enter the encryption key: ")
# cipher = AESCipher(decrypted_file_name, key)
# cipher.decrypt()
# print("File decrypted successfully.")
