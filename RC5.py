class RC5:
    def __init__(self, w=32, r=12, b=16):
        """
        Initialize the RC5 encryption algorithm with given parameters.
        :param w: Word size in bits (32, 64, 128 are common).
        :param r: Number of rounds (12 to 20 are typical).
        :param b: Key length in bytes (user key will be hashed to this length).
        """
        self.w = w  # Word size
        self.r = r  # Number of rounds
        self.b = b  # Key length in bytes
        self.mod = 2 ** self.w
        self.t = 2 * (self.r + 1)
        self.S = None  # Key schedule array

    def _left_rotate(self, x, y):
        """
        Rotate x left by y bits.
        """
        return ((x << y) & (self.mod - 1)) | (x >> (self.w - y))

    def _right_rotate(self, x, y):
        """
        Rotate x right by y bits.
        """
        return (x >> y) | ((x << (self.w - y)) & (self.mod - 1))

    def _key_schedule(self, key):
        """
        Expand the provided key into a list of subkeys stored in S.
        """
        # Convert the key into a list of bytes, then to a list of words
        L = [int.from_bytes(key[i:i+self.b], byteorder='little') for i in range(0, len(key), self.b)]
        
        # Initialize the key schedule array
        self.S = [(0xB7E15163 + i * 0x9E3779B9) % self.mod for i in range(self.t)]
        
        # Mix the key into the key schedule
        i = j = 0
        A = B = 0
        for k in range(3 * self.t):
            self.S[i] = self._left_rotate((self.S[i] + A + B) % self.mod, 3)
            A = self.S[i]
            i = (i + 1) % self.t
            L[j] = self._left_rotate((L[j] + A + B) % self.mod, (A + B) % self.w)
            B = L[j]
            j = (j + 1) % len(L)

    def encrypt_block(self, data):
        """
        Encrypt a block of data with RC5.
        """
        A = int.from_bytes(data[:self.b], byteorder='little') + self.S[0]
        B = int.from_bytes(data[self.b:self.b*2], byteorder='little') + self.S[1]
        
        for i in range(1, self.r + 1):
            A = (self._left_rotate(A ^ B, B) + self.S[2 * i]) % self.mod
            B = (self._left_rotate(B ^ A, A) + self.S[2 * i + 1]) % self.mod
        
        return (A.to_bytes(self.b, byteorder='little') +
                B.to_bytes(self.b, byteorder='little'))

    def decrypt_block(self, data):
        """
        Decrypt a block of data with RC5.
        """
        A = int.from_bytes(data[:self.b], byteorder='little')
        B = int.from_bytes(data[self.b:self.b*2], byteorder='little')
        
        for i in range(self.r, 0, -1):
            B = self._right_rotate(B - self.S[2 * i + 1], A) ^ A
            A = self._right_rotate(A - self.S[2 * i], B) ^ B

        return ((A - self.S[0]).to_bytes(self.b, byteorder='little') +
                (B - self.S[1]).to_bytes(self.b, byteorder='little'))

# Example usage (this should be uncommented and run outside of the PCI by the user)
# rc5 = RC5()
# key = b'example key 1234'
# rc5._key_schedule(key)
# encrypted = rc5.encrypt_block(b'This is a test 1234')
# decrypted = rc5.decrypt_block(encrypted)
# print('Encrypted:', encrypted)
# print('Decrypted:', decrypted)
