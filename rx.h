#ifndef RX_H
#define RX_H

#include <stdint.h>

int rx_process(
    const uint8_t *packet,
    unsigned long long packet_len,
    const uint8_t key[32],
    char *message
);

#endif