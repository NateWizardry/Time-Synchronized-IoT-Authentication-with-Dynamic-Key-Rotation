#ifndef TX_H
#define TX_H

#include <stdint.h>

int tx_process(
    const char *message,
    const uint8_t key[32],
    uint8_t *packet,
    unsigned long long *packet_len
);

#endif