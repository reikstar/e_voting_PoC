import base64
from hashlib import sha512
import threading
from src.packages.Utils.RFC3526Groups import dh_groups
import gmpy2 as gmp
import json
import os
HEADERSIZE = 30
file_lock = threading.Lock()

def hex_to_base64(hex_string):
    hex_string = hex_string.replace(" ", "").replace("\n", "")
    byte_array = bytes.fromhex(hex_string)
    return base64.b64encode(byte_array).decode("utf-8")

def int_to_base64(value: int):
    bytes_num = (value.bit_length() + 7) // 8
    byte_array = value.to_bytes(bytes_num, 'big')
    return base64.b64encode(byte_array).decode("utf-8")

def base64_to_int(string):
    bytes = base64.b64decode(string)
    value = int.from_bytes(bytes, 'big')
    return value


def get_rfc_group(id):
    if id not in dh_groups:
        grp_id = [x for x in dh_groups]
        raise AttributeError(f"""Group id is not existing in list.
                Id available:{grp_id}""")

    bits = dh_groups[id].get("bits")
    hex_string = dh_groups[id].get("hex_value").replace(" ", "").replace("\n", "")
    modulus = int(hex_string, 16)
    generator = dh_groups[id].get("generator")

    return (bits, modulus, generator)



###json utils

def read_from_json(path):
    with file_lock:
        if os.path.exists(path):
            with open(path, 'r') as file:
                return json.load(file)
        else:
            return []


def write_to_json(path, data):
    with file_lock:
        with open(path, 'w') as file:
            json.dump(data, file, indent=3)

def append_to_json(path, data):
    with file_lock:
        with open(path, 'a') as file:
            json.dump(data, file, indent=3)


def return_user_params(index, path):

    with open (path, "r") as json_file:
        data = json.load(json_file)[index]
        pub_key = base64_to_int(data.get("PUB_KEY"))
        modulus = base64_to_int(data.get("MODULUS"))
        generator = base64_to_int(data.get("GENERATOR"))

    return (modulus, generator, pub_key)


def fiat_shamir(*args):
    """
    Generate challenge via sha512 using the passed arguments.

    :return: Hash digest casted to int.
    """
    h = sha512()
    hash_input = ""

    for arg in args:
        hash_input += str(arg)

    h.update(hash_input.encode())
    challenge = int(h.hexdigest(), 16)

    return challenge

def get_str_val(other_info):
    return str(other_info) if other_info is not None else ""

def get_root_directory():
    current_directory = os.path.dirname(os.path.abspath(__file__))
    root_directory = os.path.abspath(os.path.join(current_directory, '..', '..', '..'))
    
    return root_directory


def invert_ciphertext(ciphertext, modulus):
    x = gmp.invert(ciphertext[0], modulus)
    y = gmp.invert(ciphertext[1], modulus)

    return (x, y)
