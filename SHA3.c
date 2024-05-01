#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

// Function to perform SHA-3 hashing
void sha3_hash(const char *input, unsigned char *output, size_t *output_len) {
    EVP_MD_CTX *mdctx;  // OpenSSL digest context

    // Initialize the digest context
    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        perror("Failed to create digest context");
        exit(1);
    }

    // Initialize the digest computation for SHA-3
    if(EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1) {
        perror("Failed to initialize digest");
        exit(1);
    }

    // Provide the input to the digest function
    if(EVP_DigestUpdate(mdctx, input, strlen(input)) != 1) {
        perror("Failed to update digest");
        exit(1);
    }

    // Finalize the digest and get the output
    if(EVP_DigestFinal_ex(mdctx, output, (unsigned int *)output_len) != 1) {
        perror("Failed to finalize digest");
        exit(1);
    }

    // Clean up the digest context
    EVP_MD_CTX_free(mdctx);
}

// Main function to take user input and compute hash
int main() {
    char input[1024];   // Buffer for user input
    unsigned char output[EVP_MAX_MD_SIZE];  // Buffer for hash output
    size_t output_len = 0;  // Length of the hash output

    printf("Enter the input string: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("Failed to read input\n");
        return 1;
    }

    // Remove newline character if present
    input[strcspn(input, "\n")] = 0;

    // Calculate the SHA-3 hash
    sha3_hash(input, output, &output_len);

    // Print the output hash
    printf("SHA-3 hash: ");
    for(size_t i = 0; i < output_len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    return 0;
}
