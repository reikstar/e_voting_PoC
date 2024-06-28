import threading
import pickle
from secrets import randbelow, randbits
import socket
import os
from src.packages.AsymmetricCiphers.ElGamal import AddElGamal, MulElGamal
from src.packages.Utils.network_utils import get_socket_msg, send_msg
from src.packages.Utils.utils import base64_to_int, get_root_directory, int_to_base64, read_from_json, write_to_json
from src.packages.ZKPs.SecretSharing import VerifiableSecretSharing
import src.packages.ZKPs.VerifiableElGamal as ElGamalZKP


votes_directory = os.path.join(get_root_directory(), "vote_data")
current_dir = os.path.dirname(os.path.abspath(__file__))
param_path = os.path.join(current_dir, "group_params.json")
auth_path = os.path.join(current_dir, "auth_params.json")
poly_path = os.path.join(current_dir, "polynomial_commitments.json")

BOARD_ADDRESS = ('localhost', 9990)

def set_cipher_setup():
    data = read_from_json(param_path)[0]
    modulus = base64_to_int(data.get("MODULUS"))
    generator = base64_to_int(data.get("GENERATOR"))

    cipher = MulElGamal(1, predefined_group=True)
    cipher.generate_params((modulus, generator))
    cipher.generate_keys()
    return cipher

def set_additive_cipher():
    data = read_from_json(param_path)[0]
    modulus = base64_to_int(data.get("MODULUS"))
    generator = base64_to_int(data.get("GENERATOR"))
    beta = 4

    cipher = AddElGamal(1, predefined_group=True)
    cipher.generate_params((modulus, generator, beta))
    return cipher

def get_protocol_pub_key():
    data = read_from_json(param_path)[0]
    pub_key = base64_to_int(data["PUB_KEY"])

    return pub_key

def share_pub_key(authority_number, cipher, port):
    priv_key = int_to_base64(cipher.priv_key)
    pub_key = int_to_base64(cipher.pub_key)
    entry = {
        "AUTH_NO": authority_number,
        "PUB_KEY": pub_key,
        "PRIV_KEY": priv_key,
        "PORT": port,
    }

    data = read_from_json(auth_path)
    data.append(entry)
    write_to_json(auth_path, data)

def get_share_and_verify(auth_number, auth_port, cipher):
    board_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        board_socket.connect(BOARD_ADDRESS)
        board_message = get_socket_msg(board_socket)
        print(board_message.decode('utf-8'))
        send_msg(board_socket, str(auth_number))

        board_message = get_socket_msg(board_socket)
        encrypted_share = pickle.loads(board_message) # encrypted share
        print(f"Encrypted share {encrypted_share}")

        params = read_from_json(param_path)[0]
        threshold = int(params["THRESHOLD"])
        data = read_from_json(poly_path)
        poly_commitments = pickle.loads(bytes.fromhex(data))
    
        ss = VerifiableSecretSharing(cipher.modulus, cipher.q, cipher.generator, threshold)       
        is_correct_share = ss.verify_share(auth_number, encrypted_share, poly_commitments, cipher.priv_key)

        if is_correct_share:
            print("OK")
        else:
            print("INVALID SHARE")

    except ConnectionError as e:
        print(f"Connection error: {e}")

def next_authority_port(auth_number):
    data = read_from_json(auth_path)
    for entry in data:
        if entry["AUTH_NO"] == auth_number + 1:
            return entry["PORT"]
    return None

def get_vote_encryption_data(voter_id, auth_number):
    if auth_number == 1:
        data = read_from_json(param_path)
        first_data = data[0]["YES_VOTE"]
        second_data = data[0]["NO_VOTE"]
    else:
        path = os.path.join(votes_directory, f"voter_{voter_id}.json")
        data = read_from_json(path)
        first_data = data[auth_number-1]["FIRST_VOTE"]
        second_data = data[auth_number-1]["SECOND_VOTE"]

    first_vote = pickle.loads(bytes.fromhex(first_data))
    second_vote = pickle.loads(bytes.fromhex(second_data))
    return [first_vote, second_vote]

def get_voter_credentials(voter_id):
    path = os.path.join(votes_directory, f"voter_{voter_id}.json")
    data = read_from_json(path)
    
    pub_key = base64_to_int(data[0]["PUB_KEY"])
    modulus = base64_to_int(data[0]["MODULUS"])
    generator = base64_to_int(data[0]["GENERATOR"])
    return pub_key, modulus, generator


def re_encrypt_votes_and_shuffle(auth_number, voter_id, cipher):
    pub_key = get_protocol_pub_key() 

    votes = get_vote_encryption_data(voter_id, auth_number)
    first_vote = votes[0]
    second_vote = votes[1]

    rnd_val1 = randbelow(cipher.q)
    rnd_val2 = randbelow(cipher.q)
    re_encrypted_first = cipher.re_encrypt(first_vote, rnd_val1, pub_key)
    re_encrypted_second = cipher.re_encrypt(second_vote, rnd_val2, pub_key)
    re_enc_list = [re_encrypted_first, re_encrypted_second]

    switched = randbits(1)
    if switched == 1:  # assume initial order is 0 -> yes, 1 -> no
        re_enc_list = [re_encrypted_second, re_encrypted_first]

    first_proof = ElGamalZKP.re_encryption_or_proof(cipher.modulus, cipher.q, cipher.generator, pub_key, first_vote, (0-switched)%2, rnd_val1, re_enc_list)
    second_proof = ElGamalZKP.re_encryption_or_proof(cipher.modulus, cipher.q, cipher.generator, pub_key, second_vote, (1-switched)%2, rnd_val2, re_enc_list)

    return re_enc_list, first_proof, second_proof, rnd_val1, rnd_val2, switched

def post_re_encrypt_and_shuffle_proof(re_enc_list, first_proof, second_proof, voter_id):
    first_hex = bytes.hex(pickle.dumps(re_enc_list[0]))
    second_hex = bytes.hex(pickle.dumps(re_enc_list[1]))

    first_proof_hex = bytes.hex(pickle.dumps(first_proof))
    second_proof_hex = bytes.hex(pickle.dumps(second_proof))

    path = os.path.join(votes_directory, f"voter_{voter_id}.json")
    data = read_from_json(path)
    entry = {
        "FIRST_VOTE": first_hex,
        "SECOND_VOTE": second_hex,
        "FIRST_PROOF": first_proof_hex,
        "SECOND_PROOF": second_proof_hex
    }
    data.append(entry)
    write_to_json(path, data)

def get_designated_proofs(voter_id, auth_number, re_enc_list, rnd_val1, rnd_val2, switched, cipher):
    pub_key = get_protocol_pub_key()

    votes = get_vote_encryption_data(voter_id, auth_number)
    first_vote = votes[0]
    second_vote = votes[1]

    credentials = get_voter_credentials(voter_id)
    voter_pub_key = credentials[0]
    first_proof = ElGamalZKP.re_encryption_proof(cipher.modulus, cipher.q, cipher.generator, voter_pub_key, pub_key, rnd_val1, first_vote, re_enc_list[(0-switched)%2])
    second_proof = ElGamalZKP.re_encryption_proof(cipher.modulus, cipher.q, cipher.generator, voter_pub_key, pub_key, rnd_val2, second_vote, re_enc_list[(1-switched)%2])

    return first_proof, second_proof

def send_voter_proofs(voter_socket, first_proof, second_proof, switched, cipher=MulElGamal):
    data = (first_proof, second_proof, switched)
    data = pickle.dumps(data)
    int_val = int.from_bytes(data)

    encrypted_data = cipher.encrypt(int_val, cipher.pub_key)
    byte_encrypted_data = pickle.dumps(encrypted_data)

    send_msg(voter_socket, byte_encrypted_data)

def handle_voter(auth_number, voter_socket):
    add_cipher = set_additive_cipher()
    voter_id = get_socket_msg(voter_socket).decode('utf-8')

    voter_params = get_voter_credentials(voter_id)
    voter_cipher = MulElGamal(1, True)
    voter_cipher.generate_params((voter_params[1],voter_params[2]))
    voter_cipher.set_keys(voter_params[0],1)

    output = re_encrypt_votes_and_shuffle(auth_number, voter_id, add_cipher)
    post_re_encrypt_and_shuffle_proof(output[0], output[1], output[2], voter_id)
    send_msg(voter_socket, "Please verify re-encryption list.")

    desig_proofs = get_designated_proofs(voter_id, auth_number, output[0], output[3], output[4], output[5], add_cipher)
    send_voter_proofs(voter_socket, desig_proofs[0], desig_proofs[1], output[5], voter_cipher)

    next_port = next_authority_port(auth_number)
    if next_port is None:
        send_msg(voter_socket, "Please cast your vote.")
    else:
        send_msg(voter_socket, str(next_port))

    voter_socket.close()

def vote_process(auth_number, port):
    address = ('localhost', port)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(address)
    server.listen()
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_voter, args=(auth_number, conn))
        thread.start()

def start():
    not_known = True
    print("""Commands: 
          1-> Register and share key
          2-> Receive secret share
          3-> Start voting process.""")
    
    while True:
        command = input()

        if not_known and command == "1":
            print("Please select authority number:")
            auth_number = int(input())

            print("Please select port number:")
            auth_port = int(input())

            cipher = set_cipher_setup()
            share_pub_key(auth_number, cipher, auth_port)
            not_known = False
            continue

        if command == "2":
            get_share_and_verify(auth_number, auth_port, cipher)

        if command == "3":
            vote_process(auth_number, auth_port)

start()