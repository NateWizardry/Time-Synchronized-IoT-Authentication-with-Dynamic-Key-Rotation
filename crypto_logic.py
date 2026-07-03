from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def encrypt(plaintext, key, nonce, aad):
    cipher = ChaCha20Poly1305(key)
    return cipher.encrypt(nonce, plaintext, aad)


def decrypt(nonce, data, key, aad):
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, data, aad)