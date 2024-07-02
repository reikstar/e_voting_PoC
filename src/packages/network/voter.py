import pickle
import socket
import os
from Crypto.Util.number import long_to_bytes
from src.packages.AsymmetricCiphers.ElGamal import AddElGamal, MulElGamal
from src.packages.ZKPs.Schnorr import generate_proof
import src.packages.ZKPs.VerifiableElGamal as ElGamalZKP
from src.packages.Utils.network_utils import get_socket_msg, send_msg
from src.packages.Utils.utils import (
    base64_to_int,
    int_to_base64,
    read_from_json,
    get_root_directory,
    write_to_json,
)

SIZE = 1
current_dir = os.path.dirname(os.path.abspath(__file__))
filepath = os.path.join(current_dir, "id_card.json")
votes_directory = os.path.join(get_root_directory(), "vote_data")
current_dir = os.path.dirname(os.path.abspath(__file__))
param_path = os.path.join(current_dir, "group_params.json")
auth_path = os.path.join(current_dir, "auth_params.json")
poly_path = os.path.join(current_dir, "polynomial_commitments.json")


voter_cipher = MulElGamal(SIZE, True)

# Read data from id_card and set group parameters.
data = read_from_json(filepath)
name = data.get("NAME")
pub_k = base64_to_int(data.get("PUB_KEY"))
priv_key = base64_to_int(data.get("PRIV_KEY"))
modulus = base64_to_int(data.get("MODULUS"))
generator = base64_to_int(data.get("GENERATOR"))

voter_cipher.generate_params((modulus, generator))
voter_cipher.set_keys(pub_k, priv_key)


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


def get_vote_encryption_data(voter_id, auth_number):
    if auth_number == 1:
        data = read_from_json(param_path)
        first_data = data[0]["YES_VOTE"]
        second_data = data[0]["NO_VOTE"]
    else:
        path = os.path.join(votes_directory, f"voter_{voter_id}.json")
        data = read_from_json(path)
        first_data = data[auth_number - 1]["FIRST_VOTE"]
        second_data = data[auth_number - 1]["SECOND_VOTE"]

    first_vote = pickle.loads(bytes.fromhex(first_data))
    second_vote = pickle.loads(bytes.fromhex(second_data))
    return [first_vote, second_vote]


def authentication(name, pub_key, priv_key, p, q, generator):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect(("localhost", 9999))

        not_authenticated = True
        data = (name, int_to_base64(pub_key))

        while not_authenticated:
            server_msg = get_socket_msg(server_socket).decode("utf-8")
            print(server_msg)

            if not_authenticated:
                msg = pickle.dumps(data)
                send_msg(server_socket, msg)

                server_msg = get_socket_msg(server_socket).decode("utf-8")

                if server_msg == "OK":
                    zk_proof = generate_proof(p, q, generator, priv_key, pub_key)

                    msg = pickle.dumps(zk_proof)
                    send_msg(server_socket, msg)

                    server_msg = get_socket_msg(server_socket).decode("utf-8")
                    print(server_msg)
                    auth_port = get_socket_msg(server_socket).decode("utf-8")
                    server_socket.close()
                    print(f"auth port: {auth_port}")
                    return auth_port

                else:
                    print(server_msg)

                not_authenticated = False  # Update authentication state

    except ConnectionError as e:
        print(f"Connection error: {e}")


def get_vote_proofs(auth_number):
    path = os.path.join(votes_directory, f"voter_{name}.json")
    data = read_from_json(path)
    first_data = data[auth_number]["FIRST_PROOF"]
    second_data = data[auth_number]["SECOND_PROOF"]

    first_proof = pickle.loads(bytes.fromhex(first_data))
    second_proof = pickle.loads(bytes.fromhex(second_data))
    return first_proof, second_proof


def verify_re_encryption_list(auth_number, cipher=AddElGamal):
    prev_votes = get_vote_encryption_data(name, auth_number)
    print(prev_votes)
    re_enc_list = get_vote_encryption_data(name, auth_number + 1)
    print(re_enc_list)

    pub_key = get_protocol_pub_key()
    proofs = get_vote_proofs(auth_number)
    commitment_first = proofs[0][0]
    commitment_second = proofs[1][0]
    response_first = proofs[0][1]
    response_second = proofs[1][1]

    first_check = ElGamalZKP.re_encryption_or_verify(
        cipher.modulus,
        cipher.q,
        cipher.generator,
        pub_key,
        prev_votes[0],
        re_enc_list,
        commitment_first,
        response_first,
    )
    second_check = ElGamalZKP.re_encryption_or_verify(
        cipher.modulus,
        cipher.q,
        cipher.generator,
        pub_key,
        prev_votes[1],
        re_enc_list,
        commitment_second,
        response_second,
    )

    if first_check == True and second_check == True:
        return True
    else:
        return False


def verify_designated_proofs(auth_number, proofs, add_cipher=AddElGamal):
    pub_key = get_protocol_pub_key()
    prev_votes = get_vote_encryption_data(name, auth_number)
    re_enc_list = get_vote_encryption_data(name, auth_number + 1)
    switched = proofs[2]

    first_check = ElGamalZKP.re_encryption_verify(
        add_cipher.modulus,
        add_cipher.q,
        add_cipher.generator,
        voter_cipher.pub_key,
        pub_key,
        proofs[0][0],
        proofs[0][1],
        prev_votes[0],
        re_enc_list[(0 - switched) % 2],
    )
    second_check = ElGamalZKP.re_encryption_verify(
        add_cipher.modulus,
        add_cipher.q,
        add_cipher.generator,
        voter_cipher.pub_key,
        pub_key,
        proofs[1][0],
        proofs[1][1],
        prev_votes[1],
        re_enc_list[(1 - switched) % 2],
    )

    if first_check == True and second_check == True:
        return True
    else:
        return False


def get_proofs_from_encryptions(data=bytes):
    encrypted_data = pickle.loads(data)
    decrypted_data = voter_cipher.decrypt(encrypted_data)
    decrypted_bytes = long_to_bytes(decrypted_data)

    proofs = pickle.loads(decrypted_bytes)

    return proofs


def handle_authority(auth_port, auth_number, add_cipher, switched=0):
    try:
        authority_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        authority_socket.connect(("localhost", auth_port))
        send_msg(authority_socket, name.encode("utf-8"))

        msg = get_socket_msg(authority_socket).decode("utf-8")
        print(msg)

        print(
            f"Verification of re-encryption list is: {verify_re_encryption_list(auth_number, add_cipher)}"
        )
        msg = get_socket_msg(authority_socket)
        output = get_proofs_from_encryptions(msg)
        switched = (switched + output[2]) % 2

        print(
            f"Verification of designated verifier proofs is: {verify_designated_proofs(auth_number, output, add_cipher)}"
        )
        msg = get_socket_msg(authority_socket).decode("utf-8")
        if msg == "Please cast your vote.":
            print(msg)
            if switched == 1:
                print("Order is SWITCHED!")
            if switched == 0:
                print("Order is EQUAL.")

            invalid_input = True
            while invalid_input:
                print("Input 1 for first vote, or 2 for second vote.")
                vote = input()
                if vote == "1" or vote == "2":
                    vote_file = os.path.join(votes_directory, f"voter_{name}.json")

                    data = read_from_json(vote_file)
                    data.append({"CASTED_VOTE": vote})
                    write_to_json(vote_file, data)
                    invalid_input = False
                else:
                    print("Invalid input.")

            authority_socket.close()
        else:
            next_auth_port = int(msg)
            authority_socket.close()
            handle_authority(next_auth_port, auth_number + 1, add_cipher, switched)
    except Exception as e:
        print(f"Error handling authority at port {auth_port}: {e}")
        authority_socket.close()


def start():
    authenticated = False
    while True:
        print("Commands:\n 1 --> Start authentication\n 2 --> Connect to authority")
        command = input()

        if command == "1":
            if not authenticated:
                try:
                    auth_port = int(
                        authentication(
                            name,
                            voter_cipher.pub_key,
                            voter_cipher.priv_key,
                            voter_cipher.modulus,
                            voter_cipher.q,
                            voter_cipher.generator,
                        )
                    )
                    authenticated = True
                except Exception as e:
                    print(f"Authentication error: {e}")
        elif command == "2":
            try:
                if not authenticated:
                    print("You need to authenticate first to get the authority port.")
                    continue
                cipher = set_additive_cipher()
                handle_authority(auth_port, 1, cipher)
            except Exception as e:
                print(f"Error: {e}")
            break


start()
