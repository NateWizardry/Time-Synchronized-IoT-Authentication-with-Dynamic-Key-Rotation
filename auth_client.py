import socket
import threading

from config import HOST, PORT
from packet import send_packet, recv_packet

from rx import rx_process
from tx import tx_process
from client_registry import get_key

from client_registry import load_registry, save_key

current_auth_key = None
current_crypto_key = None
pending_registration_device = None

def receiver(sock):

    global current_auth_key

    while True:

        try:

            packet = recv_packet(sock)

            if packet is None:
                break

            packet_type = packet[0]

            payload = packet[1:]

            if packet_type == 0:

                msg = payload.decode()

            elif packet_type == 1:

                msg = rx_process(
                    payload,
                    current_crypto_key
                )

            else:

                print("Unknown packet type.")
                continue
            
            if msg == "ALIVE?":

                send_encrypted(
                    sock,
                    "ALIVE_ACK"
                )

                continue

            if msg.startswith("KEY_UPDATE"):

                _, key = msg.split()

                current_auth_key = int(key)

                print(
                    f"\n[NEW AUTH KEY] {hex(current_auth_key)}"
                )

            else:

                print(f"\n{msg}")

                if msg.startswith("REGISTERED"):

                    global pending_registration_device

                    if pending_registration_device is not None:

                        _, key = msg.split()

                        save_key(
                            pending_registration_device,
                            key
                        )

                        print(
                            f"[CLIENT] ChaCha key stored for {pending_registration_device}"
                        )

                        pending_registration_device = None

        except Exception as e:

            print(f"\nConnection closed ({e})")
            break

def send_encrypted(sock, message):

    packet = tx_process(
        message,
        current_crypto_key
    )

    payload = b"\x01" + packet

    send_packet(
        sock,
        payload
    )
    
def main():

    global pending_registration_device

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.connect((HOST, PORT))

    load_registry()

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

        parts = cmd.strip().split()

        global current_crypto_key

        if len(parts) == 2 and parts[0].upper() == "LOGIN":

            current_crypto_key = get_key(parts[1])

            if current_crypto_key is None:
                print("No ChaCha key stored for this device.")
                continue

        if len(parts) == 2 and parts[0].upper() == "REGISTER":
            pending_registration_device = parts[1]

        protected_commands = {
            "LOGOUT",
            "ALIVE_ACK"
        }

        command = parts[0].upper()

        if current_crypto_key is not None and command in protected_commands:

            send_encrypted(
                sock,
                cmd
            )

        else:

            payload = b"\x00" + cmd.encode()

            send_packet(
                sock,
                payload
            )

    sock.close()


if __name__ == "__main__":
    main()