import os

from crypto_logic import encrypt

AAD = b"AUTH_PROTOCOL_V1"


def tx_process(message, key):

    nonce = os.urandom(12)

    encrypted = encrypt(
        message.encode(),
        key,
        nonce,
        AAD
    )

    return nonce + encrypted