#ifndef CRYPTO_LOGIC_H
#define CRYPTO_LOGIC_H

#include <stdint.h>

#define NONCE_SIZE 12
#define TAG_SIZE 16
#define KEY_SIZE 32

int encrypt(
    const uint8_t *plaintext,
    unsigned long long plaintext_len,
    const uint8_t key[KEY_SIZE],
    const uint8_t nonce[NONCE_SIZE],
    const uint8_t *aad,
    unsigned long long aad_len,
    uint8_t *ciphertext,
    unsigned long long *ciphertext_len
);

int decrypt(
    const uint8_t *ciphertext,
    unsigned long long ciphertext_len,
    const uint8_t key[KEY_SIZE],
    const uint8_t nonce[NONCE_SIZE],
    const uint8_t *aad,
    unsigned long long aad_len,
    uint8_t *plaintext,
    unsigned long long *plaintext_len
);

#endif