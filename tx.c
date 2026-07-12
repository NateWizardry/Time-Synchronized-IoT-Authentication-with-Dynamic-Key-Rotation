#include "tx.h"
#include "crypto_logic.h"

#include <string.h>

#include <sodium.h>

static const uint8_t AAD[] = "AUTH_PROTOCOL_V1";

int tx_process(
    const char *message,
    const uint8_t key[32],
    uint8_t *packet,
    unsigned long long *packet_len
)
{
    uint8_t *nonce = packet;

    randombytes_buf(
        nonce,
        NONCE_SIZE
    );

    unsigned long long encrypted_len;

    if (
        encrypt(
            (const uint8_t *)message,
            strlen(message),
            key,
            nonce,
            AAD,
            sizeof(AAD) - 1,
            packet + NONCE_SIZE,
            &encrypted_len
        ) != 0
    )
    {
        return -1;
    }

    *packet_len =
        NONCE_SIZE +
        encrypted_len;

    return 0;
}