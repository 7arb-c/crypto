import os
import hashlib

class OneTimePadCipher:
    def __init__(self, key=None):
        self.key = key
        self.file_size = None

    def set_key(self, key):
        if not key:
            raise ValueError("Key cannot be empty")
        self.key = key

    def validate_file(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError("File does not exist")
        self._calculate_file_size(file_path)
        return file_path

    def _calculate_file_size(self, file_path):
        self.file_size = os.path.getsize(file_path)

    def _generate_full_key(self):
        if not self.key:
            raise ValueError("Key has not been set")
        hashed_key = hashlib.sha256(self.key.encode()).hexdigest()
        full_key = (hashed_key * (self.file_size // len(hashed_key) + 1))[:self.file_size]
        return bytes(full_key, 'utf-8')

    def encrypt(self, file_path):
        file_path = self.validate_file(file_path)
        data = open(file_path, 'rb').read()
        full_key = self._generate_full_key()
        encrypted_data = bytes([b ^ full_key[i] for i, b in enumerate(data)])
        new_file_path = file_path.rsplit('.', 1)[0]  # remove extension
        with open(new_file_path, 'wb') as file:
            file.write(encrypted_data)
        os.remove(file_path)  # delete the original file

    def decrypt(self, encrypted_file_path, output_file_path):
        encrypted_file_path = self.validate_file(encrypted_file_path)
        data = open(encrypted_file_path, 'rb').read()
        full_key = self._generate_full_key()
        decrypted_data = bytes([b ^ full_key[i] for i, b in enumerate(data)])
        with open(output_file_path, 'wb') as file:
            file.write(decrypted_data)
        os.remove(encrypted_file_path)  # optional: remove the encrypted file
