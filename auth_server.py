import socket
import threading
import time
from registration_manager import generate_crypto_key
from packet import send_packet, recv_packet

from rx import rx_process

from config import HOST, PORT, MAX_CLIENTS, HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT
from key_manager import generate_auth_key, KEY_ROTATION_INTERVAL

from device_registry import (
    load_registry,
    register_device,
    deregister_device,
    device_exists,
    get_device,
    update_device_parameters,
    get_all_devices
)

from tx import tx_process

connected_clients = {}          # in memory database
lock = threading.Lock()         # mutex for modifying database

def send_encrypted(conn, message, crypto_key):

    encrypted = tx_process(
        message,
        crypto_key
    )

    payload = b"\x01" + encrypted

    send_packet(
        conn,
        payload
    )

def send(conn, msg):

    payload = b"\x00" + msg.encode()

    send_packet(
        conn,
        payload
    )

def print_connected_clients():
    print("\n=== CONNECTED CLIENTS ===")

    if not connected_clients:
        print("None")

    for i, device in enumerate(connected_clients, start=1):
        print(f"{i}. {device}")

    print("=========================\n")

def handle_client(conn, addr):
    print(f"[CONNECTED] {addr}")

    device_name = None          # nobody logged in

    try:
        while True:

            packet = recv_packet(conn)

            if packet is None:
                break

            packet_type = packet[0]

            payload = packet[1:]

            if packet_type == 0:

                msg = payload.decode()

            elif packet_type == 1:

                if device_name is None:

                    send(conn, "FAIL: Not authenticated")
                    continue

                msg = rx_process(
                    payload,
                    connected_clients[device_name]["crypto_key"]
                )

            else:

                send(conn, "FAIL: Invalid packet type")
                continue

            parts = msg.strip().split()

            if not parts:
                continue

            if packet_type == 1:

                if len(parts) < 2:
                    send(conn, "FAIL: Invalid protected message")
                    continue

                try:
                    received_auth_key = int(parts[0])

                except ValueError:
                    send(conn, "FAIL: Invalid authentication key")
                    continue

                expected_auth_key = connected_clients[device_name]["auth_key"]

                if received_auth_key != expected_auth_key:

                    send(conn, "FAIL: Invalid authentication key")
                    continue

                command = parts[1].upper()
                parts = parts[1:]

            else:

                command = parts[0].upper()

            # ---------------- REGISTER ----------------
            if command == "REGISTER":

                    if len(parts) != 2:
                        send(conn, "FAIL: REGISTER <device_name>")
                        continue

                    requested_device = parts[1]

                    with lock:

                        if device_exists(requested_device):
                            send(conn, "FAIL: Device already registered")
                            continue

                        crypto_key = generate_crypto_key()

                        register_device(
                            requested_device,
                            crypto_key
                        )

                    send(
                        conn,
                        f"REGISTERED {crypto_key.hex()}"
                    )

                    print(
                        f"[REGISTERED] {requested_device}"
                    )

                    print(
                        f"ChaCha Key: {crypto_key.hex()}"
                    )

                    continue

            # ---------------- LOGIN ----------------
            if command == "LOGIN":

                    if len(parts) != 2:         # must have 2 parts eg: LOGIN nathan
                        send(conn, "FAIL: LOGIN <device_name>")
                        continue

                    requested_device = parts[1]

                    with lock:

                        if not device_exists(requested_device):      # not registered
                            send(conn, "FAIL: Device not registered")
                            continue

                        if requested_device in connected_clients:           # duplicate
                            send(conn, "FAIL: Device already connected")
                            continue

                        if len(connected_clients) >= MAX_CLIENTS:           # max limit
                            send(conn, "FAIL: Server full")
                            continue

                        initial_key = generate_auth_key()

                        device_info = get_device(requested_device)

                        crypto_key = bytes.fromhex(
                            device_info["crypto_key"]
                        )

                        connected_clients[requested_device] = {
                            "socket": conn,
                            "last_seen": time.time(),
                            "auth_key": initial_key,
                            "crypto_key": crypto_key
                        }

                        device_name = requested_device

                    send(conn, "SUCCESS")
                    send(conn, f"KEY_UPDATE {initial_key}")
                    print(f"Assigned key to {device_name}: {hex(initial_key)}")

                    print(f"[LOGIN] {device_name}")
                    print_connected_clients()

            # ---------------- LOGOUT ----------------
            elif command == "LOGOUT":

                    if device_name is None:
                        send(conn, "FAIL: Not logged in")
                        continue

                    with lock:
                        connected_clients.pop(device_name, None)            # remove from database

                    print(f"[LOGOUT] {device_name}")
                    print_connected_clients()

                    device_name = None

                    send(conn, "SUCCESS")

            # ---------------- HANDLE ALIVE_ACK ----------------

            elif command == "ALIVE_ACK":
                print(f"Received ALIVE_ACK from {device_name}")
                with lock:

                    if device_name in connected_clients:

                        connected_clients[device_name]["last_seen"] = time.time()

            # ---------------- UNKNOWN ----------------
            else:
                    send(conn, "FAIL: Unknown command")

    finally:

        if device_name:

            with lock:
                connected_clients.pop(device_name, None)

            print(f"[DISCONNECTED] {device_name}")
            print_connected_clients()

        conn.close()


def start_server():

    load_registry()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)          # AF_INET → IPv4, SOCK_STREAM → TCP

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen()

    print(f"[STARTED] Server running on {HOST}:{PORT}")

    threading.Thread(
        target=key_rotation_worker,
        daemon=True
    ).start()

    print("[KEY MANAGER] Started")

    threading.Thread(
        target=heartbeat_worker,
        daemon=True
    ).start()

    print("[HEARTBEAT] Started")

    while True:

        conn, addr = server.accept()

        threading.Thread(           # threads so multiple clients can co-exist
            target=handle_client,
            args=(conn, addr),
            daemon=True
        ).start()

def key_rotation_worker():
    
    while True:

        time.sleep(KEY_ROTATION_INTERVAL)

        with lock:

            if not connected_clients:
                continue

            print("\n[KEY ROTATION STARTED]\n")

            for device, info in list(connected_clients.items()):

                new_key = generate_auth_key()

                info["auth_key"] = new_key

                try:

                    send_encrypted(
                        info["socket"],
                        f"KEY_UPDATE {new_key}",
                        info["crypto_key"]
                    )

                    print(
                        f"{device} -> {hex(new_key)}"
                    )

                except:
                    print(
                        f"Failed to update {device}"
                    )

            print()

def heartbeat_worker():

    while True:

        time.sleep(HEARTBEAT_INTERVAL)

        with lock:

            for device, info in list(connected_clients.items()):

                if time.time() - info["last_seen"] > HEARTBEAT_TIMEOUT:

                    print(
                        f"{device} timed out."
                    )

                    try:
                        info["socket"].close()
                    except:
                        pass

                    connected_clients.pop(device)

                    continue

                try:

                    print(f"Sending ALIVE? to {device}")

                    send_encrypted(
                        info["socket"],
                        "ALIVE?",
                        info["crypto_key"]
                    )

                except:
                    pass

if __name__ == "__main__":
    start_server()