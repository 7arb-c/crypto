class IDEA:
    def __init__(self, file_path, user_key=None):
        self.file_path = file_path
        self.key = None
        if user_key:
            self.set_key(user_key)

    def set_key(self, user_key):
        import hashlib
        hasher = hashlib.sha256()
        hasher.update(user_key.encode())
        self.key = hasher.digest()[:16]  # Use first 128 bits / 16 bytes of the hash as the key

    def validate_file(self):
        import os
        if not os.path.exists(self.file_path):
            raise FileNotFoundError("The specified file does not exist")

    def read_file(self):
        with open(self.file_path, "rb") as file:
            return file.read()

    def write_file(self, data, suffix):
        import os
        path, ext = os.path.splitext(self.file_path)
        new_path = f"{path}_{suffix}{ext}"
        with open(new_path, "wb") as file:
            file.write(data)

    def generate_subkeys(self):
        # This function would generate the necessary subkeys from the main key
        # Placeholder for subkey expansion logic
        pass

    def encrypt_block(self, block):
        # Placeholder for block encryption logic
        pass

    def decrypt_block(self, block):
        # Placeholder for block decryption logic
        pass

    def encrypt(self):
        self.validate_file()
        data = self.read_file()
        encrypted_data = b''
        # Placeholder for actual encryption logic using blocks
        self.write_file(encrypted_data, "encrypted")

    def decrypt(self):
        self.validate_file()
        data = self.read_file()
        decrypted_data = b''
        # Placeholder for actual decryption logic using blocks
        self.write_file(decrypted_data, "decrypted")


# Example usage (commented out for safety):
# idea = IDEA("path/to/file.txt", "userkey123")
# idea.encrypt()
# idea.decrypt()
