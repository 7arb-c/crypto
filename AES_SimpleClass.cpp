#include <iostream>
#include <fstream>
#include <openssl/aes.h>
#include <openssl/rand.h>

class AESCipher {
private:
    const int AES_BLOCK_SIZE = 16;
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

public:
    AESCipher(const unsigned char* key_data) {
        memcpy(key, key_data, AES_BLOCK_SIZE);
        RAND_bytes(iv, AES_BLOCK_SIZE);
    }

    void encryptFile(const std::string& file_name) {
        std::ifstream in_file(file_name, std::ios::binary);
        if (!in_file) {
            std::cerr << "Error opening input file" << std::endl;
            return;
        }

        in_file.seekg(0, std::ios::end);
        std::streampos file_size = in_file.tellg();
        in_file.seekg(0, std::ios::beg);

        unsigned char* plaintext = new unsigned char[file_size];
        in_file.read(reinterpret_cast<char*>(plaintext), file_size);
        in_file.close();

        AES_KEY aes_key;
        AES_set_encrypt_key(key, 256, &aes_key);

        unsigned char* ciphertext = new unsigned char[file_size + AES_BLOCK_SIZE];
        AES_cbc_encrypt(plaintext, ciphertext, file_size, &aes_key, iv, AES_ENCRYPT);

        std::ofstream out_file(file_name + ".enc", std::ios::binary);
        if (!out_file) {
            std::cerr << "Error opening output file" << std::endl;
            delete[] plaintext;
            delete[] ciphertext;
            return;
        }

        out_file.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);
        out_file.write(reinterpret_cast<const char*>(ciphertext), file_size + AES_BLOCK_SIZE);

        out_file.close();
        delete[] plaintext;
        delete[] ciphertext;

        std::cout << "File encrypted successfully." << std::endl;
    }
};

int main() {
    const unsigned char key[] = "my_secret_key";
    std::string file_name = "example.txt";

    AESCipher aesCipher(key);
    aesCipher.encryptFile(file_name);

    return 0;
}
