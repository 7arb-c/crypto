#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>

#define P_ARRAY_SIZE 18
#define S_BOX_COUNT 4
#define S_BOX_SIZE 256

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
    
    int j = 0;
    for (int i = 0; i < P_ARRAY_SIZE; i++) {
        cipher->P[i] = (key_hash[j] << 24) | (key_hash[(j+1) % SHA256_DIGEST_LENGTH] << 16) |
                       (key_hash[(j+2) % SHA256_DIGEST_LENGTH] << 8) | key_hash[(j+3) % SHA256_DIGEST_LENGTH];
        j = (j + 4) % SHA256_DIGEST_LENGTH;
    }

    // Initialize S-boxes (dummy values for now)
    for (int i = 0; i < S_BOX_COUNT; i++) {
        for (int k = 0; k < S_BOX_SIZE; k++) {
            cipher->S[i][k] = (i * S_BOX_SIZE + k) % 256;
        }
    }
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
    blowfish_cipher_free(cipher);

    return 0;
}
