#include "rx.h"
#include "crypto_logic.h"

#include <string.h>

static const uint8_t AAD[] = "AUTH_PROTOCOL_V1";

int rx_process(
    const uint8_t *packet,
    unsigned long long packet_len,
    const uint8_t key[32],
    char *message
)
{
    const uint8_t *nonce = packet;

    const uint8_t *encrypted =
        packet + NONCE_SIZE;

    unsigned long long encrypted_len =
        packet_len - NONCE_SIZE;

    unsigned long long plaintext_len;

    if (
        decrypt(
            encrypted,
            encrypted_len,
            key,
            nonce,
            AAD,
            sizeof(AAD) - 1,
            (uint8_t *)message,
            &plaintext_len
        ) != 0
    )
    {
        return -1;
    }

    message[plaintext_len] = '\0';

    return 0;
}