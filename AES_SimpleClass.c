#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define AES_BLOCK_SIZE 16

void encrypt_file(const char *file_name, const unsigned char *key) {
    FILE *in_file = fopen(file_name, "rb");
    if (!in_file) {
        perror("Error opening input file");
        return;
    }

    fseek(in_file, 0L, SEEK_END);
    long file_size = ftell(in_file);
    rewind(in_file);

    unsigned char *plaintext = (unsigned char *)malloc(file_size);
    if (!plaintext) {
        perror("Memory allocation error");
        fclose(in_file);
        return;
    }

    fread(plaintext, 1, file_size, in_file);
    fclose(in_file);

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 256, &aes_key) < 0) {
        perror("Error setting AES encryption key");
        free(plaintext);
        return;
    }

    unsigned char *ciphertext = (unsigned char *)malloc(file_size + AES_BLOCK_SIZE);
    if (!ciphertext) {
        perror("Memory allocation error");
        free(plaintext);
        return;
    }

    int ciphertext_len;
    AES_cbc_encrypt(plaintext, ciphertext, file_size, &aes_key, iv, AES_ENCRYPT);
    ciphertext_len = file_size;

    FILE *out_file = fopen(strcat(file_name, ".enc"), "wb");
    if (!out_file) {
        perror("Error opening output file");
        free(plaintext);
        free(ciphertext);
        return;
    }

    fwrite(iv, 1, AES_BLOCK_SIZE, out_file);
    fwrite(ciphertext, 1, ciphertext_len, out_file);

    fclose(out_file);
    free(plaintext);
    free(ciphertext);

    printf("File encrypted successfully.\n");
}

int main() {
    const char *file_name = "example.txt";
    const unsigned char *key = "my_secret_key";

    encrypt_file(file_name, key);

    return 0;
}
