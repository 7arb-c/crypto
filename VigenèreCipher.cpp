#include <iostream>
#include <string>
#include <cctype>

class VigenereCipher {
private:
    std::string key;

    bool is_valid_key(const std::string &key) const {
        for (char ch : key) {
            if (!isalpha(ch)) return false;
        }
        return true;
    }

public:
    VigenereCipher(const std::string &key) {
        set_key(key);
    }

    void set_key(const std::string &key) {
        if (!is_valid_key(key)) {
            throw std::invalid_argument("Invalid key. Key must be alphabetic.");
        }
        this->key = key;
    }

    std::string encrypt(const std::string &message) {
        if (!is_valid_key(key)) {
            throw std::runtime_error("Encryption key not set or invalid.");
        }

        std::string encrypted;
        int key_len = key.length();
        for (size_t i = 0; i < message.length(); i++) {
            if (!isalpha(message[i])) {
                throw std::invalid_argument("Invalid message. Message must be alphabetic.");
            }
            int key_shift = toupper(key[i % key_len]) - 'A';
            int encrypted_char = toupper(message[i]) - 'A';
            encrypted += 'A' + (encrypted_char + key_shift) % 26;
        }
        return encrypted;
    }
};

int main() {
    try {
        VigenereCipher cipher("KEY");
        std::string message = "HELLO";
        std::string encrypted = cipher.encrypt(message);
        std::cout << "Encrypted message: " << encrypted << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}
