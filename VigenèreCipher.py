class VigenereCipher:
    def __init__(self, key=None):
        self.key = key
        self.message = None
        if key is not None:
            self.set_key(key)

    def set_key(self, key):
        if self._is_valid_key(key):
            self.key = key
        else:
            raise ValueError("Invalid key. The key must be alphabetic.")

    def set_message(self, message):
        if self._is_valid_message(message):
            self.message = message
        else:
            raise ValueError("Invalid message. The message must be alphabetic.")

    def encrypt(self):
        if not self.message:
            raise ValueError("No message has been set for encryption.")
        if not self.key:
            raise ValueError("No key has been set for encryption.")

        return self._encrypt_message()

    def _encrypt_message(self):
        key_length = len(self.key)
        key_as_int = [ord(i.upper()) - ord('A') for i in self.key]
        message_int = [ord(i.upper()) - ord('A') for i in self.message]
        cipher_text = ''

        for i in range(len(message_int)):
            value = (message_int[i] + key_as_int[i % key_length]) % 26
            cipher_text += chr(value + ord('A'))

        return cipher_text

    def _is_valid_key(self, key):
        return key.isalpha()

    def _is_valid_message(self, message):
        return message.isalpha()

# Usage
cipher = VigenereCipher('KEY')
cipher.set_message('HELLO')
encrypted_message = cipher.encrypt()
print(f'Encrypted message: {encrypted_message}')
