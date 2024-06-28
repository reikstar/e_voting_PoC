import pickle
from secrets import randbelow
import socket
import threading
from src.packages.AsymmetricCiphers.ElGamal import AddElGamal, MulElGamal
from src.packages.Utils.network_utils import get_socket_msg, send_msg
from src.packages.Utils.utils import base64_to_int, get_rfc_group, int_to_base64, read_from_json, write_to_json
import os
import gmpy2 as gmp

from src.packages.ZKPs.SecretSharing import VerifiableSecretSharing
from src.packages.math.mod_expo import base_k_exp
PORT = 9990
ADDRESS = (('localhost', PORT))

K = 3

current_dir = os.path.dirname(os.path.abspath(__file__))
param_path = os.path.join(current_dir,"group_params.json")
auth_path = os.path.join(current_dir,"auth_params.json")
poly_path = os.path.join(current_dir,"polynomial_commitments.json")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(ADDRESS)
server.settimeout(30)

def set_cipher_setup():
    data = read_from_json(param_path)[0]
    modulus = base64_to_int(data.get("MODULUS"))
    generator = base64_to_int(data.get("GENERATOR"))
    
    cipher = MulElGamal(1, predefined_group=True)
    cipher.generate_params((modulus, generator))
    
    return cipher

def setup_group_params(bits, predifined_group_id = None): #before pub key available to vote

    if predifined_group_id is None:
        cipher = MulElGamal(bits)
        cipher.generate_params()
    
    else:
        params = get_rfc_group(predifined_group_id)
        modulus = params[1]
        generator = params[2]
        ElGamalParams = (modulus, generator)

        cipher = MulElGamal(bits, predefined_group=True)
        cipher.generate_params(ElGamalParams)

    params = int_to_base64(cipher.modulus), int_to_base64(cipher.generator)

    entry = {
        "MODULUS": params[0],
        "GENERATOR": params[1],
    }
    
    data = read_from_json(param_path)
    data.append(entry)
    write_to_json(param_path, data)


def get_auth_keys():
    data = read_from_json(auth_path)
    pub_keys = []
    sorted_data = sorted(data, key= lambda x:x["AUTH_NO"])
    for entry in sorted_data:
        pub_keys.append(base64_to_int(entry.get("PUB_KEY")))
    
    return pub_keys

def gen_shares(threshold,cipher):
    keys = get_auth_keys()
    secret = randbelow(cipher.q)
    
    pub_key = int(base_k_exp(cipher.generator, secret, cipher.modulus, K))

    data = read_from_json(param_path)
    data[0]["PUB_KEY"] = int_to_base64(pub_key)
    data[0]["THRESHOLD"] = threshold
    write_to_json(param_path, data)
    
    ss = VerifiableSecretSharing(cipher.modulus, cipher.q , cipher.generator, threshold)
    shares = ss.distribute_secret(keys, secret)

    encryptions = shares[0]
    poly_commit = shares[1]
    
    data = read_from_json(auth_path)
    for entry in data:
        x = int(entry.get("AUTH_NO"))
        commitment = ss.call_poly_from_commitment(poly_commit, x)
        entry["SHARE_COMMITMENT"] = int_to_base64(commitment)
    write_to_json(auth_path, data)

    byte_data = pickle.dumps(poly_commit)
    data = bytes.hex(byte_data)
    write_to_json(poly_path, data)

    return encryptions


def handle_authority(auth_socket, encryption_list):
    send_msg(auth_socket, "Sent encryption.")
    number = int(get_socket_msg(auth_socket).decode('utf-8'))
    
    data = pickle.dumps(encryption_list[number - 1])
    send_msg(auth_socket, data)

    auth_socket.close()

def post_std_votes():
    data = read_from_json(param_path)
    data[0]["BETA"] = 4

    modulus = base64_to_int(data[0]["MODULUS"])
    generator = base64_to_int(data[0]["GENERATOR"])
    
    beta = 4
    additive_cipher = AddElGamal(1, True)
    additive_cipher.generate_params((modulus, generator, beta))

    yes_vote = (1, beta)
    no_vote = (1, int(gmp.invert(beta, modulus)))

    serialised_yes = pickle.dumps(yes_vote)
    serialised_no = pickle.dumps(no_vote)
    yes_data = bytes.hex(serialised_yes)
    no_data = bytes.hex(serialised_no)
    data[0]["YES_VOTE"] = yes_data
    data[0]["NO_VOTE"] = no_data
    write_to_json(param_path, data)

def start():
    print("Modulus size:")
    bits = int(input())
    setup_group_params(bits)
    cipher = set_cipher_setup()

    while True:
        print("Commands:\n1-> Give threshold size. Generate shares.")
        print("2-> Start handling authorities connections.\nIf no connection made for 30 seconds, end sharing phase.")
        print("3-> Post standard votes.")

        command = input()
        if command == "1":
            print("Threshold size:")
            threshold = int(input())
            encryptions = gen_shares(threshold, cipher)

        elif command == "2":
            server.listen()
            while True:
                try:
                    conn, addr = server.accept()
                    thread = threading.Thread(target=handle_authority, args=(conn, encryptions))
                    thread.start()
                    print("new thread started")
                except socket.timeout:
                    break

        elif command == "3":
            post_std_votes()

start()

        
    
