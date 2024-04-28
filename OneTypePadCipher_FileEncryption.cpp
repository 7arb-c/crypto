#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/sha.h>
#include <stdexcept>

class OneTimePad {
private:
    std::vector<char> key;
    size_t file_size;

    std::vector<char> generateFullKey() const {
        if (key.empty()) {
            throw std::runtime_error("Key has not been set");
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, key.data(), key.size());
        SHA256_Final(hash, &sha256);

        std::vector<char> full_key(file_size);
        for (size_t i = 0; i < file_size; ++i) {
            full_key[i] = hash[i % SHA256_DIGEST_LENGTH];
        }
        return full_key;
    }

public:
    OneTimePad(const std::string& keyStr) {
        if (keyStr.empty()) {
            throw std::invalid_argument("Key cannot be empty");
        }
        key.assign(keyStr.begin(), keyStr.end());
    }

    void encryptDecrypt(const std::string& inputFilePath, const std::string& outputFilePath) {
        std::ifstream inputFile(inputFilePath, std::ios::binary);
        if (!inputFile.is_open()) {
            throw std::runtime_error("Error opening input file");
        }

        inputFile.seekg(0, std::ios::end);
        file_size = inputFile.tellg();
        inputFile.seekg(0, std::ios::beg);

        std::vector<char> full_key = generateFullKey();
        std::vector<char> buffer(file_size);

        inputFile.read(buffer.data(), file_size);
        inputFile.close();

        for (size_t i = 0; i < file_size; ++i) {
            buffer[i] ^= full_key[i];
        }

        std::ofstream outputFile(outputFilePath, std::ios::binary);
        if (!outputFile.is_open()) {
            throw std::runtime_error("Error opening output file");
        }
        outputFile.write(buffer.data(), file_size);
        outputFile.close();

        // Optional: remove the input file after encryption/decryption
        std::remove(inputFilePath.c_str());
    }
};

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <key> <input file> <output file>" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        OneTimePad otp(argv[1]);
        otp.encryptDecrypt(argv[2], argv[3]);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
