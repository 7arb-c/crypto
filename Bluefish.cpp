#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdexcept>

#define P_ARRAY_SIZE 18
#define S_BOX_COUNT 4
#define S_BOX_SIZE 256
#define BLOCK_SIZE 8 // Blowfish uses 64-bit (8-byte) blocks

// Initial values for P-array and S-boxes (part of the Blowfish standard)
static const uint32_t P_INIT[P_ARRAY_SIZE] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0,
    0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B
};

// S-box initialization values are truncated for brevity
static const uint32_t S_INIT[S_BOX_COUNT][S_BOX_SIZE] = {
    { /* values */ },
    { /* values */ },
    { /* values */ },
    { /* values */ }
};

class BlowfishCipher {
public:
    BlowfishCipher(const std::string &user_key) {
        setKey(user_key);
    }

    void encryptFile(const std::string &input_filename, const std::string &output_filename) {
        std::vector<unsigned char> data = readFile(input_filename);

        size_t padded_len = ((data.size() + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
        data.resize(padded_len, 0);

        for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
            encryptBlock(reinterpret_cast<uint32_t*>(&data[i]));
        }

        writeFile(output_filename, data);
    }

    void decryptFile(const std::string &input_filename, const std::string &output_filename) {
        std::vector<unsigned char> data = readFile(input_filename);

        for (size_t i = 0; i < data.size(); i += BLOCK_SIZE) {
            decryptBlock(reinterpret_cast<uint32_t*>(&data[i]));
        }

        writeFile(output_filename, data);
    }

private:
    uint32_t P[P_ARRAY_SIZE];
    uint32_t S[S_BOX_COUNT][S_BOX_SIZE];

    void setKey(const std::string &user_key) {
        if (user_key.empty()) {
            throw std::invalid_argument("User key cannot be empty.");
        }

        unsigned char key_hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(user_key.c_str()), user_key.size(), key_hash);

        std::memcpy(P, P_INIT, sizeof(P_INIT));
        std::memcpy(S, S_INIT, sizeof(S_INIT));

        int j = 0;
        for (int i = 0; i < P_ARRAY_SIZE; i++) {
            P[i] ^= (key_hash[j] << 24) | (key_hash[(j+1) % SHA256_DIGEST_LENGTH] << 16) |
                    (key_hash[(j+2) % SHA256_DIGEST_LENGTH] << 8) | key_hash[(j+3) % SHA256_DIGEST_LENGTH];
            j = (j + 4) % SHA256_DIGEST_LENGTH;
        }

        uint32_t data[2] = {0, 0};
        for (int i = 0; i < P_ARRAY_SIZE; i += 2) {
            encryptBlock(data);
            P[i] = data[0];
            P[i + 1] = data[1];
        }

        for (int i = 0; i < S_BOX_COUNT; i++) {
            for (int k = 0; k < S_BOX_SIZE; k += 2) {
                encryptBlock(data);
                S[i][k] = data[0];
                S[i][k + 1] = data[1];
            }
        }
    }

    uint32_t F(uint32_t x) const {
        uint16_t a = (x >> 24) & 0xFF;
        uint16_t b = (x >> 16) & 0xFF;
        uint16_t c = (x >> 8) & 0xFF;
        uint16_t d = x & 0xFF;
        return ((S[0][a] + S[1][b]) ^ S[2][c]) + S[3][d];
    }

    void encryptBlock(uint32_t *data) const {
        uint32_t left = data[0];
        uint32_t right = data[1];

        for (int i = 0; i < 16; ++i) {
            left ^= P[i];
            right ^= F(left);
            std::swap(left, right);
        }

        std::swap(left, right);

        right ^= P[16];
        left ^= P[17];

        data[0] = left;
        data[1] = right;
    }

    void decryptBlock(uint32_t *data) const {
        uint32_t left = data[0];
        uint32_t right = data[1];

        for (int i = 17; i > 1; --i) {
            left ^= P[i];
            right ^= F(left);
            std::swap(left, right);
        }

        std::swap(left, right);

        right ^= P[1];
        left ^= P[0];

        data[0] = left;
        data[1] = right;
    }

    std::vector<unsigned char> readFile(const std::string &filename) const {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("Failed to open file for reading: " + filename);
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<unsigned char> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data(), size))) {
            throw std::runtime_error("Failed to read file: " + filename);
        }

        return buffer;
    }

    void writeFile(const std::string &filename, const std::vector<unsigned char> &data) const {
        std::ofstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for writing: " + filename);
        }

        if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
            throw std::runtime_error("Failed to write file: " + filename);
        }
    }
};

int main() {
    try {
        BlowfishCipher cipher("securekey");

        // Encrypt file
        cipher.encryptFile("plaintext.txt", "ciphertext.bin");

        // Decrypt file
        cipher.decryptFile("ciphertext.bin", "decrypted.txt");

        std::cout << "Encryption and decryption completed successfully." << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
