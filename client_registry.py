import json
import os

FILE_NAME = "client_keys.json"


def load_registry():

    if not os.path.exists(FILE_NAME):
        with open(FILE_NAME, "w") as f:
            json.dump({}, f, indent=4)


def save_key(device_name, crypto_key_hex):

    with open(FILE_NAME, "r") as f:
        data = json.load(f)

    data[device_name] = {
        "crypto_key": crypto_key_hex
    }

    with open(FILE_NAME, "w") as f:
        json.dump(data, f, indent=4)


def get_key(device_name):

    with open(FILE_NAME, "r") as f:
        data = json.load(f)

    if device_name not in data:
        return None

    return bytes.fromhex(
        data[device_name]["crypto_key"]
    )