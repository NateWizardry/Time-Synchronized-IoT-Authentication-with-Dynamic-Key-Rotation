import secrets


def generate_crypto_key():
    """
    Generate a 256-bit (32-byte) ChaCha20 key.
    """
    return secrets.token_bytes(32)      # generates cryptographically strong pseudo-random numbers