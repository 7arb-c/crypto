#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/md5.h>
#include <openssl/salsa.h>

#define BUFFER_SIZE 1024

void generateKey(const char *input_key, uint8_t *key) {
    // Generate MD5 hash of the input key
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)input_key, strlen(input_key), hash);

    // Use the first 32 bytes of the MD5 hash as the key
    memcpy(key, hash, 32);
}

void encryptFile(const char *file_name, const uint8_t *key) {
    FILE *in_file = fopen(file_name, "rb");
    if (!in_file) {
        perror("Error opening input file");
        return;
    }

    FILE *out_file = fopen(strcat(file_name, ".enc"), "wb");
    if (!out_file) {
        perror("Error opening output file");
        fclose(in_file);
        return;
    }

    uint8_t nonce[8] = {0}; // Nonce is set to all zeros
    uint8_t counter[8] = {0}; // Counter is set to all zeros
    salsa20_ctx ctx;
    salsa20_keysetup(&ctx, key, 256, 8);
    salsa20_ivsetup(&ctx, nonce, counter);

    uint8_t buffer[BUFFER_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, in_file)) > 0) {
        salsa20_encrypt_bytes(&ctx, buffer, buffer, bytes_read);
        fwrite(buffer, 1, bytes_read, out_file);
    }

    fclose(in_file);
    fclose(out_file);

    printf("File encrypted successfully.\n");
}

int main() {
    char file_name[256];
    printf("Enter the name of the file to encrypt: ");
    fgets(file_name, sizeof(file_name), stdin);
    file_name[strcspn(file_name, "\n")] = '\0'; // Remove newline character

    char input_key[256];
    printf("Enter the encryption key: ");
    fgets(input_key, sizeof(input_key), stdin);
    input_key[strcspn(input_key, "\n")] = '\0'; // Remove newline character

    uint8_t key[32];
    generateKey(input_key, key);

    encryptFile(file_name, key);

    return 0;
}
