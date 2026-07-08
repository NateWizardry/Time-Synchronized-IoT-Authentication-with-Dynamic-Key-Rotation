import struct


HEADER_SIZE = 4


def send_packet(sock, payload):
    """
    Sends:
    [4-byte length][payload]
    """

    length = len(payload)

    header = struct.pack("!I", length)
    # ! -> Network byte order (Big Endian)
    # I -> Unsigned 32-bit integer

    sock.sendall(header + payload)


def recv_exact(sock, size):
    """
    Receives exactly 'size' bytes.
    TCP may return fewer bytes than requested,
    so keep reading until complete.
    """

    data = b""

    while len(data) < size:

        chunk = sock.recv(size - len(data))

        if not chunk:
            return None

        data += chunk

    return data


def recv_packet(sock):
    """
    Receives one complete packet.

    Returns:
        bytes
    """

    header = recv_exact(sock, HEADER_SIZE)

    if header is None:
        return None

    length = struct.unpack("!I", header)[0]

    payload = recv_exact(sock, length)

    return payload