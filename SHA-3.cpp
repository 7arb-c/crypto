#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>

class SHA3Hasher {
public:
    SHA3Hasher() {
        mdctx = EVP_MD_CTX_new(); // Allocate context for SHA-3
        if (!mdctx) {
            throw std::runtime_error("Failed to create digest context");
        }
    }

    ~SHA3Hasher() {
        EVP_MD_CTX_free(mdctx); // Free the context
    }

    std::vector<unsigned char> hash(const std::string& input) {
        std::vector<unsigned char> output(EVP_MAX_MD_SIZE);
        unsigned int output_len = 0;

        if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1) {
            throw std::runtime_error("Failed to initialize digest");
        }

        if (EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1) {
            throw std::runtime_error("Failed to update digest");
        }

        if (EVP_DigestFinal_ex(mdctx, output.data(), &output_len) != 1) {
            throw std::runtime_error("Failed to finalize digest");
        }

        output.resize(output_len);
        return output;
    }

private:
    EVP_MD_CTX* mdctx; // OpenSSL digest context
};

int main() {
    std::string input;
    std::cout << "Enter the input string: ";
    std::getline(std::cin, input);

    try {
        SHA3Hasher hasher;
        std::vector<unsigned char> result = hasher.hash(input);

        std::cout << "SHA-3 hash: ";
        for (unsigned char byte : result) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)byte;
        }
        std::cout << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
