import random

# TESTING:
# Change to 300 later (5 minutes)
KEY_ROTATION_INTERVAL = 30


def generate_auth_key():
    return random.getrandbits(32)