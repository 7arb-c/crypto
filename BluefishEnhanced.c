#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <errno.h>

#define P_ARRAY_SIZE 18
#define S_BOX_COUNT 4
#define S_BOX_SIZE 256

// Initial values for P-array and S-boxes (part of the Blowfish standard)
static const uint32_t P_INIT[P_ARRAY_SIZE] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0,
    0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B
};

static const uint32_t S_INIT[S_BOX_COUNT][S_BOX_SIZE] = {
    // ... (actual initialization values are lengthy, truncated for brevity)
};

typedef struct {
    char *filename;
    char *user_key;
    uint32_t P[P_ARRAY_SIZE];
    uint32_t S[S_BOX_COUNT][S_BOX_SIZE];
} BlowfishCipher;

void validate_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("File validation failed");
        exit(EXIT_FAILURE);
    }
    fclose(file);
}

void key_schedule(BlowfishCipher *cipher) {
    unsigned char key_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)cipher->user_key, strlen(cipher->user_key), key_hash);

    memcpy(cipher->P, P_INIT, sizeof(P_INIT));
    memcpy(cipher->S, S_INIT, sizeof(S_INIT));

    int j = 0;
    for (int i = 0; i < P_ARRAY_SIZE; i++) {
        cipher->P[i] ^= (key_hash[j] << 24) | (key_hash[(j+1) % SHA256_DIGEST_LENGTH] << 16) |
                        (key_hash[(j+2) % SHA256_DIGEST_LENGTH] << 8) | key_hash[(j+3) % SHA256_DIGEST_LENGTH];
        j = (j + 4) % SHA256_DIGEST_LENGTH;
    }

    uint32_t data[2] = {0, 0};
    for (int i = 0; i < P_ARRAY_SIZE; i += 2) {
        blowfish_encrypt(cipher, data);
        cipher->P[i] = data[0];
        cipher->P[i + 1] = data[1];
    }

    for (int i = 0; i < S_BOX_COUNT; i++) {
        for (int k = 0; k < S_BOX_SIZE; k += 2) {
            blowfish_encrypt(cipher, data);
            cipher->S[i][k] = data[0];
            cipher->S[i][k + 1] = data[1];
        }
    }
}

uint32_t F(BlowfishCipher *cipher, uint32_t x) {
    uint16_t a = (x >> 24) & 0xFF;
    uint16_t b = (x >> 16) & 0xFF;
    uint16_t c = (x >> 8) & 0xFF;
    uint16_t d = x & 0xFF;
    return ((cipher->S[0][a] + cipher->S[1][b]) ^ cipher->S[2][c]) + cipher->S[3][d];
}

void blowfish_encrypt(BlowfishCipher *cipher, uint32_t *data) {
    uint32_t left = data[0];
    uint32_t right = data[1];

    for (int i = 0; i < 16; ++i) {
        left ^= cipher->P[i];
        right ^= F(cipher, left);
        uint32_t temp = left;
        left = right;
        right = temp;
    }

    uint32_t temp = left;
    left = right;
    right = temp;

    right ^= cipher->P[16];
    left ^= cipher->P[17];

    data[0] = left;
    data[1] = right;
}

void blowfish_decrypt(BlowfishCipher *cipher, uint32_t *data) {
    uint32_t left = data[0];
    uint32_t right = data[1];

    for (int i = 17; i > 1; --i) {
        left ^= cipher->P[i];
        right ^= F(cipher, left);
        uint32_t temp = left;
        left = right;
        right = temp;
    }

    uint32_t temp = left;
    left = right;
    right = temp;

    right ^= cipher->P[1];
    left ^= cipher->P[0];

    data[0] = left;
    data[1] = right;
}

void set_key(BlowfishCipher *cipher, const char *user_key) {
    if (!user_key || strlen(user_key) == 0) {
        fprintf(stderr, "User key cannot be empty.\n");
        exit(EXIT_FAILURE);
    }
    cipher->user_key = strdup(user_key);
    key_schedule(cipher);
}

void set_filename(BlowfishCipher *cipher, const char *filename) {
    validate_file(filename);
    cipher->filename = strdup(filename);
}

BlowfishCipher *blowfish_cipher_new(const char *filename, const char *user_key) {
    BlowfishCipher *cipher = malloc(sizeof(BlowfishCipher));
    if (!cipher) {
        perror("Failed to allocate memory for BlowfishCipher");
        exit(EXIT_FAILURE);
    }
    memset(cipher, 0, sizeof(BlowfishCipher));

    if (filename) {
        set_filename(cipher, filename);
    }
    if (user_key) {
        set_key(cipher, user_key);
    }

    return cipher;
}

void blowfish_cipher_free(BlowfishCipher *cipher) {
    if (cipher->filename) free(cipher->filename);
    if (cipher->user_key) free(cipher->user_key);
    free(cipher);
}

int main() {
    BlowfishCipher *cipher = blowfish_cipher_new("example.txt", "securekey");
    set_filename(cipher, "newfile.txt");
    set_key(cipher, "newsecurekey");

    uint32_t data[2] = {0x12345678, 0x9abcdef0};
    printf("Original: %08x %08x\n", data[0], data[1]);

    blowfish_encrypt(cipher, data);
    printf("Encrypted: %08x %08x\n", data[0], data[1]);

    blowfish_decrypt(cipher, data);
    printf("Decrypted: %08x %08x\n", data[0], data[1]);

    blowfish_cipher_free(cipher);
    return 0;
}
