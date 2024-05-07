class RC4Cipher:
    def __init__(self, key):
        """Initialize the RC4 cipher with a given key after validating it."""
        if not key:
            raise ValueError("Key must not be empty.")
        self.key = key
        self.s = list(range(256))  # Initialize state array with values 0 to 255
        self.ksa()  # Perform the key-scheduling algorithm

    def ksa(self):
        """Key-Scheduling Algorithm (KSA) to initialize the state vector."""
        j = 0
        for i in range(256):
            j = (j + self.s[i] + ord(self.key[i % len(self.key)])) % 256
            self.s[i], self.s[j] = self.s[j], self.s[i]  # Swap values

    def prga(self):
        """Pseudo-Random Generation Algorithm (PRGA) to generate keystream."""
        i = j = 0
        while True:
            i = (i + 1) % 256
            j = (j + self.s[i]) % 256
            self.s[i], self.s[j] = self.s[j], self.s[i]  # Swap values
            K = self.s[(self.s[i] + self.s[j]) % 256]
            yield K

    def encrypt(self, plaintext):
        """Encrypt or decrypt the input (plaintext/ciphertext) using the RC4 cipher."""
        keystream = self.prga()
        return bytes([c ^ next(keystream) for c in plaintext])

    @staticmethod
    def read_file(file_path):
        """Read file content after validating its existence."""
        import os
        if not os.path.exists(file_path):
            raise FileNotFoundError("The file does not exist.")
        with open(file_path, 'rb') as file:  # Open file in binary mode
            data = file.read()
        return data

    @staticmethod
    def write_file(file_path, data):
        """Write data to a file."""
        with open(file_path, 'wb') as file:  # Open file in binary mode
            file.write(data)

    def encrypt_file(self, file_path, output_path):
        """Encrypt a file using the RC4 cipher."""
        data = self.read_file(file_path)
        encrypted_data = self.encrypt(data)
        self.write_file(output_path, encrypted_data)
        return output_path

# Sample usage (commented out for initial code writing purposes):
# cipher = RC4Cipher("secret")
# cipher.encrypt_file("path/to/input/file", "path/to/output/file")

