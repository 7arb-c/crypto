#include <stdio.h>
#include <string.h>
#include <ctype.h>

int is_valid_key(const char *key) {
    for (int i = 0; key[i] != '\0'; i++) {
        if (!isalpha(key[i])) return 0;
    }
    return 1;
}

int encrypt(const char *key, const char *message, char *encrypted) {
    if (!is_valid_key(key)) {
        printf("Invalid key. Key must be alphabetic.\n");
        return -1;
    }

    int key_len = strlen(key);
    int msg_len = strlen(message);

    for (int i = 0; i < msg_len; i++) {
        if (!isalpha(message[i])) {
            printf("Invalid message. Message must be alphabetic.\n");
            return -2;
        }
        int key_shift = toupper(key[i % key_len]) - 'A';
        int encrypted_char = toupper(message[i]) - 'A';
        encrypted[i] = 'A' + (encrypted_char + key_shift) % 26;
    }
    encrypted[msg_len] = '\0';
    return 0;
}

int main() {
    char key[] = "KEY";
    char message[] = "HELLO";
    char encrypted[100];

    if (encrypt(key, message, encrypted) == 0) {
        printf("Encrypted message: %s\n", encrypted);
    }

    return 0;
}
