#ifndef CLIENT_REGISTRY_H
#define CLIENT_REGISTRY_H

#include <stdint.h>

int load_registry(void);

int save_key(
    const char *device,
    const char *hex_key
);

int get_key(
    const char *device,
    uint8_t key[32]
);

#endif