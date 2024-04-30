import os

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.backends import default_backend



class Encryption:

    def __init__(self):

        self.file_path = None

        self.user_key = None

        self.file_size = None

        self.full_key = None



    def set_file(self, file_path):

        self.file_path = file_path

        self._check_file()



    def set_key(self, key):

        self.user_key = key.encode()  # Ensure key is in bytes



    def _check_file(self):

        """Check if file exists and calculate its size."""

        if not os.path.exists(self.file_path):

            raise FileNotFoundError("The specified file does not exist")

        self.file_size = os.path.getsize(self.file_path)

        self._generate_full_key()



    def _generate_full_key(self):

        """Generate a full-size key by hashing the user key and repeating it."""

        hash_key = hashlib.sha256(self.user_key).digest()

        repetitions = (self.file_size // len(hash_key)) + 1

        self.full_key = (hash_key * repetitions)[:self.file_size]



    def encrypt(self):

        """Encrypt the file content and write to new file then delete the original."""

        with open(self.file_path, 'rb') as file:

            original_data = file.read()

        

        # First XOR operation

        xored_data = self._xor_data(original_data, self.full_key)

        

        # Salsa20 encryption

        encrypted_data = self._salsa20_encrypt(xored_data)

        

        # Second XOR operation

        final_data = self._xor_data(encrypted_data, self.full_key)

        

        # Write encrypted data to a new file and delete the original

        encrypted_file_path = self.file_path + ".enc"

        with open(encrypted_file_path, 'wb') as encrypted_file:

            encrypted_file.write(final_data)

        

        # Delete the original file securely by overwriting

        self._secure_delete_original()



        return encrypted_file_path



    def decrypt(self, encrypted_file_path):

        """Decrypt the encrypted content and restore the original file."""

        with open(encrypted_file_path, 'rb') as file:

            encrypted_data = file.read()



        xored_data = self._xor_data(encrypted_data, self.full_key)

        decrypted_salsa20 = self._salsa20_decrypt(xored_data)

        original_data = self._xor_data(decrypted_salsa20, self.full_key)

        

        original_file_path = encrypted_file_path.rstrip(".enc")

        with open(original_file_path, 'wb') as original_file:

            original_file.write(original_data)

        

        os.remove(encrypted_file_path)

        

        return original_file_path



    def _xor_data(self, data, key):

        """XOR operation between data and the key."""

        return bytes(a ^ b for a, b in zip(data, key))



    def _salsa20_encrypt(self, data):

        """Encrypt data using the Salsa20 algorithm."""

        backend = default_backend()

        key_hash = hashlib.sha256(self.user_key).digest()[:32]  # 256-bit key for Salsa20

        cipher = Cipher(algorithms.Salsa20(key_hash, os.urandom(8)), mode=None, backend=backend)

        encryptor = cipher.encryptor()

        return encryptor.update(data) + encryptor.finalize()



    def _salsa20_decrypt(self, data):

        """Decrypt data using the Salsa20 algorithm."""

        backend = default_backend()

        key_hash = hashlib.sha256(self.user_key).digest()[:32]  # 256-bit key for Salsa20

        cipher = Cipher(algorithms.Salsa20(key_hash, os.urandom(8)), mode=None, backend=backend)

        decryptor = cipher.decryptor()

        return decryptor.update(data) + decryptor.finalize()



    def _secure_delete_original(self):

        """Securely delete the original file by overwriting."""

        with open(self.file_path, 'rb+') as file:

            length = file.tell()

            file.seek(0)

            file.write(os.urandom(length))  # Overwrite with random data

        os.remove(self.file_path)  # Finally, delete the file



# Example of setting file and key, encrypting and decrypting

# encryption = Encryption()

# encryption.set_key('secretkey')

# encryption.set_file('example.txt')

# encrypted_file = encryption.encrypt()

# decrypted_file = encryption.decrypt(encrypted_file)

# assert open(decrypted_file, 'rb').read() == open('example.txt', 'rb').read(), "Decryption failed"


