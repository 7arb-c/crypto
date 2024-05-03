from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class DSA:
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key if public_key else private_key.public_key()

    @staticmethod
    def generate_keys(key_size=2048):
        """
        Generates a DSA key pair.
        
        :param key_size: The key size in bits. Recommended to be at least 2048 bits.
        :return: DSA class instance with generated private and public keys.
        """
        private_key = dsa.generate_private_key(key_size=key_size)
        return DSA(private_key=private_key)

    def sign_message(self, message):
        """
        Signs a message with the private key.

        :param message: The message to sign.
        :return: Signature as bytes.
        """
        # Ensuring the message is in bytes
        if isinstance(message, str):
            message = message.encode()

        # Signing the message
        signature = self.private_key.sign(message, hashes.SHA256())
        return signature

    @staticmethod
    def verify_signature(public_key, message, signature):
        """
        Verifies the signature of a message.

        :param public_key: The public key to use for verification.
        :param message: The original message that was signed.
        :param signature: The signature to verify.
        :return: True if the signature is valid, False otherwise.
        """
        # Ensuring the message is in bytes
        if isinstance(message, str):
            message = message.encode()

        try:
            public_key.verify(signature, message, hashes.SHA256())
            return True
        except InvalidSignature:
            return False

# Example of how to use the class will be provided after the review.
