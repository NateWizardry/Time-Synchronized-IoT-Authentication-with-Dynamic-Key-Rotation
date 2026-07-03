from crypto_logic import decrypt

AAD = b"AUTH_PROTOCOL_V1"


def rx_process(packet, key):

    nonce = packet[:12]

    encrypted = packet[12:]

    plaintext = decrypt(
        nonce,
        encrypted,
        key,
        AAD
    )

    return plaintext.decode()