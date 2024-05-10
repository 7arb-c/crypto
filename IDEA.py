class IDEA:
    def __init__(self, file_path, user_key=None):
        self.file_path = file_path
        self.key = None
        self.subkeys = []
        if user_key:
            self.set_key(user_key)

    def set_key(self, user_key):
        import hashlib
        hasher = hashlib.sha256()
        hasher.update(user_key.encode())
        self.key = hasher.digest()[:16]  # Use first 128 bits / 16 bytes of the hash as the key
        self.generate_subkeys()

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
        from itertools import cycle
        key_int = int.from_bytes(self.key, byteorder='big')
        rotations = [key_int]
        # Generate 52 subkeys
        for i in range(1, 52):
            key_int = ((key_int << 25) | (key_int >> (128 - 25))) & ((1 << 128) - 1)  # 25-bit rotation
            rotations.append(key_int)
        self.subkeys = [(int.from_bytes((rotation).to_bytes(16, byteorder='big')[i:i+2], byteorder='big') & 0xFFFF) for rotation in rotations for i in range(0, 16, 2)]

    def encrypt_block(self, block):
        block = int.from_bytes(block, byteorder='big')
        for i in range(0, len(self.subkeys), 6):
            # Placeholder for IDEA's rounds
            k = self.subkeys[i:i+6]  # Each round uses 6 keys
            # Assume some transformations (this is just a placeholder)
            block = (block + k[0]) % 0x10000
        return block.to_bytes(8, byteorder='big')  # Return bytes

    def decrypt_block(self, block):
        block = int.from_bytes(block, byteorder='big')
        for i in range(len(self.subkeys)-6, -1, -6):
            k = self.subkeys[i:i+6]  # Reverse round
            # Assume reverse transformations
            block = (block - k[0]) % 0x10000
        return block.to_bytes(8, byteorder='big')  # Return bytes

    def encrypt(self):
        self.validate_file()
        data = self.read_file()
        encrypted_data = b''
        # Encrypt data in 8-byte blocks
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            block = block.ljust(8, b'\0')  # Pad block if not full
            encrypted_block = self.encrypt_block(block)
            encrypted_data += encrypted_block
        self.write_file(encrypted_data, "encrypted")

    def decrypt(self):
        self.validate_file()
        data = self.read_file()
        decrypted_data = b''
        # Decrypt data in 8-byte blocks
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            decrypted_block = self.decrypt_block(block)
            decrypted_data += decrypted_block
        self.write_file(decrypted_data, "decrypted")

# Comment out function and method calls to avoid execution in the PCI
# idea = IDEA("path/to/file.txt", "userkey123")
# idea.encrypt()
# idea.decrypt()
