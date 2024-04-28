#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <errno.h>

struct OneTimePad {
    char *key;
    size_t file_size;
};

void handle_error(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

size_t calculate_file_size(const char *file_path) {
    struct stat stat_buf;
    if (stat(file_path, &stat_buf) == -1) {
        handle_error("Error getting file size");
    }
    return stat_buf.st_size;
}

void set_key(struct OneTimePad *otp, const char *key) {
    if (key == NULL || strlen(key) == 0) {
        fprintf(stderr, "Key cannot be empty\n");
        exit(EXIT_FAILURE);
    }
    otp->key = strdup(key);
    if (otp->key == NULL) {
        handle_error("Memory allocation for key failed");
    }
}

char *generate_full_key(struct OneTimePad *otp) {
    if (otp->key == NULL) {
        fprintf(stderr, "Key has not been set\n");
        exit(EXIT_FAILURE);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, otp->key, strlen(otp->key));
    SHA256_Final(hash, &sha256);

    char *full_key = malloc(otp->file_size);
    if (full_key == NULL) {
        handle_error("Memory allocation for full key failed");
    }

    for (size_t i = 0; i < otp->file_size; i++) {
        full_key[i] = hash[i % SHA256_DIGEST_LENGTH];
    }
    return full_key;
}

void encrypt_decrypt_file(const char *input_file_path, const char *output_file_path, struct OneTimePad *otp) {
    otp->file_size = calculate_file_size(input_file_path);
    char *full_key = generate_full_key(otp);

    FILE *input_file = fopen(input_file_path, "rb");
    if (input_file == NULL) {
        handle_error("Error opening input file");
    }

    FILE *output_file = fopen(output_file_path, "wb");
    if (output_file == NULL) {
        handle_error("Error opening output file");
    }

    char buffer;
    size_t index = 0;
    while (fread(&buffer, 1, 1, input_file) == 1) {
        char encrypted_char = buffer ^ full_key[index++];
        fwrite(&encrypted_char, 1, 1, output_file);
    }

    fclose(input_file);
    fclose(output_file);
    free(full_key);

    // Optional: Remove the input file after encryption
    remove(input_file_path);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <key> <input file> <output file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct OneTimePad otp;
    set_key(&otp, argv[1]);
    encrypt_decrypt_file(argv[2], argv[3], &otp);
    free(otp.key);

    return EXIT_SUCCESS;
}
