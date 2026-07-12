#include "crypto_logic.h"

#include <sodium.h>

int encrypt(
    const uint8_t *plaintext,
    unsigned long long plaintext_len,
    const uint8_t key[KEY_SIZE],
    const uint8_t nonce[NONCE_SIZE],
    const uint8_t *aad,
    unsigned long long aad_len,
    uint8_t *ciphertext,
    unsigned long long *ciphertext_len
)
{
    return crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext,
        ciphertext_len,
        plaintext,
        plaintext_len,
        aad,
        aad_len,
        NULL,
        nonce,
        key
    );
}

int decrypt(
    const uint8_t *ciphertext,
    unsigned long long ciphertext_len,
    const uint8_t key[KEY_SIZE],
    const uint8_t nonce[NONCE_SIZE],
    const uint8_t *aad,
    unsigned long long aad_len,
    uint8_t *plaintext,
    unsigned long long *plaintext_len
)
{
    return crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext,
        plaintext_len,
        NULL,
        ciphertext,
        ciphertext_len,
        aad,
        aad_len,
        nonce,
        key
    );
}