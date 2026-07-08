import json
import os
import threading

FILE_NAME = "registered_devices.json"

registry_lock = threading.Lock()


def load_registry():

    with registry_lock:

        if not os.path.exists(FILE_NAME):
            with open(FILE_NAME, "w") as f:
                json.dump({}, f, indent=4)


def _read_data():

    with open(FILE_NAME, "r") as f:
        return json.load(f)


def _write_data(data):

    with open(FILE_NAME, "w") as f:
        json.dump(data, f, indent=4)


def register_device(device_name, crypto_key):

    with registry_lock:

        data = _read_data()

        data[device_name] = {
            "crypto_key": crypto_key.hex()
        }

        _write_data(data)


def deregister_device(device_name):

    with registry_lock:

        data = _read_data()

        data.pop(device_name, None)

        _write_data(data)


def device_exists(device_name):

    with registry_lock:

        data = _read_data()

        return device_name in data


def get_device(device_name):

    with registry_lock:

        data = _read_data()

        return data.get(device_name)


def update_device_parameters(device_name, **kwargs):

    with registry_lock:

        data = _read_data()

        if device_name not in data:
            return False

        data[device_name].update(kwargs)

        _write_data(data)

        return True


def get_all_devices():

    with registry_lock:

        return _read_data()