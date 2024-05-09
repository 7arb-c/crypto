# Class to implement the Blowfish cipher from scratch

class BlowfishCipher:
    def __init__(self, filename=None, user_key=None):
        self.filename = filename
        self.user_key = user_key
        self.P = []
        self.S = []
        if self.user_key:
            self.set_key(self.user_key)
        if self.filename:
            self.validate_file()

    def set_key(self, user_key):
        """
        Set the user key with validation and then initialize key scheduling
        """
        if not user_key:
            raise ValueError("User key cannot be empty.")
        self.user_key = user_key
        self.key_schedule()  # Initialize the key scheduling

    def set_filename(self, filename):
        """
        Set the filename after validating its existence.
        """
        self.filename = filename
        self.validate_file()

    def validate_file(self):
        """
        Validate that the file exists.
        """
        import os
        if not os.path.isfile(self.filename):
            raise FileNotFoundError("The file does not exist.")
        
    def key_schedule(self):
        """
        Initialize the P-array and S-boxes using the hashed key.
        """
        from hashlib import sha256
        key_hash = sha256(self.user_key.encode()).digest()  # Hash the user key
        
        # Initialize P-array and S-boxes (using a dummy approach here)
        # Actual Blowfish requires detailed setup
        self.P = [0] * 18
        self.S = [[0] * 256 for _ in range(4)]
        
        # Dummy key expansion (replace with actual Blowfish logic)
        j = 0
        for i in range(len(self.P)):
            self.P[i] = int.from_bytes(key_hash[j:j+4], 'big')
            j = (j + 4) % len(key_hash)

# Dummy function calls for testing (commented out for now)
# cipher = BlowfishCipher("example.txt", "securekey")
# cipher.set_filename("newfile.txt")
# cipher.set_key("newsecurekey")

