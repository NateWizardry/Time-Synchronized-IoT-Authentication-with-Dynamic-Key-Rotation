import socket
import threading

from config import HOST, PORT

current_auth_key = None


def receiver(sock):

    global current_auth_key

    buffer = ""

    while True:

        try:

            data = sock.recv(1024).decode()

            if not data:
                break

            buffer += data

            while "\n" in buffer:

                msg, buffer = buffer.split("\n", 1)

                msg = msg.strip()

                if not msg:
                    continue

                if msg.startswith("KEY_UPDATE"):

                    _, key = msg.split()

                    current_auth_key = int(key)

                    print(
                        f"\n[NEW AUTH KEY] {hex(current_auth_key)}"
                    )

                else:

                    print(f"\n{msg}")

        except:
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

        sock.sendall((cmd + "\n").encode())

    sock.close()


if __name__ == "__main__":
    main()