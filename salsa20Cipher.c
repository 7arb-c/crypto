#include <stdio.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

// Function to hash the passphrase to generate a 256-bit key
void derive_key(unsigned char *key, const char *passphrase) {
    crypto_generichash(key, crypto_generichash_BYTES, (const unsigned char *)passphrase, strlen(passphrase), NULL, 0);
}

// Encrypt or decrypt the data
void salsa20_encrypt_decrypt(const char *input_file_name, const char *output_file_name, const unsigned char *key) {
    // Open the input file
    FILE *input_file = fopen(input_file_name, "rb");
    if (!input_file) {
        perror("Failed to open input file");
        exit(EXIT_FAILURE);
    }

    // Open the output file
    FILE *output_file = fopen(output_file_name, "wb");
    if (!output_file) {
        perror("Failed to open output file");
        fclose(input_file);
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[4096];
    unsigned char nonce[crypto_stream_salsa20_NONCEBYTES] = {0}; // Using a zero nonce for simplicity, use a unique nonce in real applications
    unsigned long long nonce_counter = 0;
    size_t read_size;

    // Read and process each block of the file
    while ((read_size = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {
        crypto_stream_salsa20_xor_ic(buffer, buffer, read_size, nonce, nonce_counter, key);
        fwrite(buffer, 1, read_size, output_file);
        nonce_counter++;
    }

    // Clean up
    fclose(input_file);
    fclose(output_file);
}

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Cannot initialize libsodium\n");
        return EXIT_FAILURE;
    }

    char passphrase[1024];
    unsigned char key[crypto_generichash_BYTES]; // 32 bytes for a 256-bit key

    printf("Enter passphrase: ");
    if (!fgets(passphrase, sizeof(passphrase), stdin)) {
        fprintf(stderr, "Failed to read passphrase\n");
        return EXIT_FAILURE;
    }

    // Remove newline character
    passphrase[strcspn(passphrase, "\n")] = 0;

    derive_key(key, passphrase);

    const char *input_file_name = "input.txt";
    const char *output_file_name = "output.txt";

    salsa20_encrypt_decrypt(input_file_name, output_file_name, key);

    printf("File encrypted successfully\n");

    return EXIT_SUCCESS;
}
