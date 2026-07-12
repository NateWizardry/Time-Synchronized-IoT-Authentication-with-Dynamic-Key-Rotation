#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sodium.h>

#include <winsock2.h>
#include <windows.h>

#include "tx.h"
#include "rx.h"
#include "client_registry.h"

#pragma comment(lib, "ws2_32.lib")

#define HOST "127.0.0.1"
#define PORT 5000

#define KEY_SIZE 32

uint32_t current_auth_key = 0;

uint8_t current_crypto_key[KEY_SIZE];

int crypto_key_loaded = 0;

char pending_registration_device[100] = "";

/*--------------------------------------------------
    Send exactly N bytes
--------------------------------------------------*/
int send_all(SOCKET sock, const void *buffer, int length)
{
    int sent = 0;

    while (sent < length)
    {
        int n = send(
            sock,
            (const char *)buffer + sent,
            length - sent,
            0
        );

        if (n <= 0)
            return 0;

        sent += n;
    }

    return 1;
}

/*--------------------------------------------------
    Receive exactly N bytes
--------------------------------------------------*/
int recv_all(SOCKET sock, void *buffer, int length)
{
    int received = 0;

    while (received < length)
    {
        int n = recv(
            sock,
            (char *)buffer + received,
            length - received,
            0
        );

        if (n <= 0)
            return 0;

        received += n;
    }

    return 1;
}

/*--------------------------------------------------
    send_packet()
--------------------------------------------------*/
int send_packet(
    SOCKET sock,
    const uint8_t *data,
    uint32_t length
)
{
    uint32_t net_length = htonl(length);

    if (!send_all(sock, &net_length, 4))
        return 0;

    if (!send_all(sock, data, length))
        return 0;

    return 1;
}

/*--------------------------------------------------
    recv_packet()
--------------------------------------------------*/
uint8_t *recv_packet(
    SOCKET sock,
    uint32_t *length
)
{
    uint32_t net_length;

    if (!recv_all(sock, &net_length, 4))
        return NULL;

    *length = ntohl(net_length);

    uint8_t *buffer = malloc(*length);

    if (buffer == NULL)
        return NULL;

    if (!recv_all(sock, buffer, *length))
    {
        free(buffer);
        return NULL;
    }

    return buffer;
}

/*--------------------------------------------------
    Receiver Thread
--------------------------------------------------*/
DWORD WINAPI receiver_thread(LPVOID arg)
{
    SOCKET sock = *(SOCKET *)arg;

    while (1)
    {
        uint32_t length;

        uint8_t *packet = recv_packet(
            sock,
            &length
        );

        if (packet == NULL)
            break;

        if (length < 1)
        {
            free(packet);
            continue;
        }

        uint8_t packet_type = packet[0];

        char message[1024];

        memset(
            message,
            0,
            sizeof(message)
        );


        /* ---------------------------
           Plaintext packet
        --------------------------- */

        if (packet_type == 0)
        {
            strcpy(
                message,
                (char *)&packet[1]
            );
        }


        /* ---------------------------
           Encrypted packet
        --------------------------- */

        else if (packet_type == 1)
        {
            if (!crypto_key_loaded)
            {
                printf("\n[ERROR] No crypto key loaded\n");

                free(packet);
                continue;
            }


            if (
                rx_process(
                    &packet[1],
                    length - 1,
                    current_crypto_key,
                    message
                ) != 0
            )
            {
                printf("\n[DECRYPT FAILED]\n");

                free(packet);
                continue;
            }
        }


        else
        {
            printf(
                "\n[UNKNOWN PACKET TYPE %u]\n",
                packet_type
            );

            free(packet);
            continue;
        }


        /* ---------------------------
           Process message
        --------------------------- */

        if (strncmp(message, "KEY_UPDATE", 10) == 0)
        {
            unsigned int key;

            sscanf(
                message,
                "KEY_UPDATE %u",
                &key
            );

            current_auth_key = key;


            printf(
                "\n[NEW AUTH KEY] 0x%08X\n",
                current_auth_key
            );
        }


        else if (strcmp(message, "ALIVE?") == 0)
        {
            printf("\n[SERVER] ALIVE?\n");

            // heartbeat response will be added next
        }


        else
        {
            printf(
                "\n%s\n",
                message
            );


            if (
                strncmp(
                    message,
                    "REGISTERED",
                    10
                ) == 0
            )
            {
                char key_hex[65];

                sscanf(
                    message,
                    "REGISTERED %64s",
                    key_hex
                );


                if (
                    strlen(
                        pending_registration_device
                    ) > 0
                )
                {
                    save_key(
                        pending_registration_device,
                        key_hex
                    );


                    printf(
                        "[CLIENT] ChaCha key stored for %s\n",
                        pending_registration_device
                    );


                    pending_registration_device[0] = '\0';
                }
            }
        }


        free(packet);
    }


    printf("\n[SERVER DISCONNECTED]\n");

    return 0;
}

/*--------------------------------------------------
    Main
--------------------------------------------------*/
int main()
{
    WSADATA wsa;

    SOCKET sock;

    struct sockaddr_in server;

    WSAStartup(MAKEWORD(2,2), &wsa);

    if (sodium_init() < 0)
    {
        printf("Failed to initialize libsodium.\n");
        return 1;
    }

    sock = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr(HOST);

    if (connect(
        sock,
        (struct sockaddr *)&server,
        sizeof(server)
    ) != 0)
    {
        printf("Connection failed.\n");
        return 1;
    }

    CreateThread(
        NULL,
        0,
        receiver_thread,
        &sock,
        0,
        NULL
    );

    printf("CONNECTED\n");

    while (1)
    {
        char input[256];

        printf("> ");

        fgets(
            input,
            sizeof(input),
            stdin
        );

        if (!strncmp(input, "EXIT", 4))
            break;

        input[strcspn(input, "\n")] = '\0';

        uint8_t payload[257];

        payload[0] = 0;

        strcpy(
            (char *)&payload[1],
            input
        );

        send_packet(
            sock,
            payload,
            1 + strlen(input)
        );
    }

    closesocket(sock);

    WSACleanup();

    return 0;
}