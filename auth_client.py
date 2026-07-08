import socket
import threading

from config import HOST, PORT
from packet import send_packet, recv_packet

current_auth_key = None


def receiver(sock):

    global current_auth_key

    while True:

        try:

            packet = recv_packet(sock)

            if packet is None:
                break

            msg = packet.decode()

            if msg.startswith("KEY_UPDATE"):

                _, key = msg.split()

                current_auth_key = int(key)

                print(
                    f"\n[NEW AUTH KEY] {hex(current_auth_key)}"
                )

            else:

                print(f"\n{msg}")

        except Exception as e:

            print(f"\nConnection closed ({e})")
            break


def main():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.connect((HOST, PORT))

    threading.Thread(
        target=receiver,
        args=(sock,),
        daemon=True
    ).start()

    print("CONNECTED")
    print("REGISTER <device>")
    print("LOGIN <device>")
    print("LOGOUT")
    print("EXIT")

    while True:

        cmd = input("> ")

        if cmd.upper() == "EXIT":
            break

        send_packet(
            sock,
            cmd.encode()
        )

    sock.close()


if __name__ == "__main__":
    main()