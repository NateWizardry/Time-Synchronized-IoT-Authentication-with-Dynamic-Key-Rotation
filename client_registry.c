#include "client_registry.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FILE_NAME "client_keys_c.txt"

int load_registry(void)
{
    FILE *fp = fopen(FILE_NAME, "a");

    if (fp == NULL)
        return 0;

    fclose(fp);

    return 1;
}

int save_key(
    const char *device,
    const char *hex_key
)
{
    FILE *fp = fopen(FILE_NAME, "a");

    if (fp == NULL)
        return 0;

    fprintf(
        fp,
        "%s %s\n",
        device,
        hex_key
    );

    fclose(fp);

    return 1;
}

int get_key(
    const char *device,
    uint8_t key[32]
)
{
    FILE *fp = fopen(FILE_NAME, "r");

    if (fp == NULL)
        return 0;

    char stored_device[100];
    char hex_key[65];

    while (
        fscanf(
            fp,
            "%99s %64s",
            stored_device,
            hex_key
        ) == 2
    )
    {
        if (strcmp(stored_device, device) == 0)
        {
            for (int i = 0; i < 32; i++)
            {
                char byte[3];

                byte[0] = hex_key[i * 2];
                byte[1] = hex_key[i * 2 + 1];
                byte[2] = '\0';

                key[i] = (uint8_t)strtoul(
                    byte,
                    NULL,
                    16
                );
            }

            fclose(fp);

            return 1;
        }
    }

    fclose(fp);

    return 0;
}