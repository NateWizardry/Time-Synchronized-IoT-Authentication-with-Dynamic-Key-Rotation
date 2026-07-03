#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define HOST "127.0.0.1"
#define PORT 5000

uint32_t current_auth_key = 0;


/*--------------------------------------
    Receiver Thread
--------------------------------------*/
DWORD WINAPI receiver_thread(LPVOID arg)
{
    SOCKET sock = *(SOCKET *)arg;

    char buffer[1024];
    char message[2048] = "";

    while (1)
    {
        memset(buffer, 0, sizeof(buffer));

        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);

        if (bytes <= 0)
            break;

        buffer[bytes] = '\0';

        strcat(message, buffer);

        char *newline;

        while ((newline = strchr(message, '\n')) != NULL)
        {
            *newline = '\0';

            if (strncmp(message, "KEY_UPDATE", 10) == 0)
            {
                unsigned int key;

                sscanf(message, "KEY_UPDATE %u", &key);

                current_auth_key = key;

                printf(
                    "\n[NEW AUTH KEY] 0x%08X\n",
                    current_auth_key
                );
            }
            else
            {
                printf("\n%s\n", message);
            }

            memmove(
                message,
                newline + 1,
                strlen(newline + 1) + 1
            );
        }
    }

    printf("\n[SERVER DISCONNECTED]\n");

    return 0;
}


/*--------------------------------------
    Main
--------------------------------------*/
int main()
{
    WSADATA wsa;
    SOCKET sock;

    struct sockaddr_in server;

    char input[100];

    /* Initialize Winsock */
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Create TCP socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr(HOST);

    /* Connect */
    if (connect(sock, (struct sockaddr *)&server,
                sizeof(server)) != 0)
    {
        printf("Connection failed.\n");
        return 1;
    }

    /* Start receiver thread */
    CreateThread(
        NULL,
        0,
        receiver_thread,
        &sock,
        0,
        NULL
    );

    printf("CONNECTED\n");

    printf("Commands:\n");
    printf("LOGIN <device>\n");
    printf("LOGOUT\n");
    printf("EXIT\n");

    while (1)
    {
        printf("> ");

        fgets(input, sizeof(input), stdin);

        if (strncmp(input, "EXIT", 4) == 0)
            break;

        send(sock, input, strlen(input), 0);
    }

    closesocket(sock);

    WSACleanup();

    printf("DISCONNECTED\n");

    return 0;
}