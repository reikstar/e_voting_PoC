import os
from src.packages.Utils.utils import read_from_json, write_to_json, int_to_base64
from src.packages.AsymmetricCiphers.ElGamal import AddElGamal, MulElGamal
import socket
import threading
import pickle
from src.packages.Utils.network_utils import get_socket_msg, send_msg
from src.packages.Utils.utils import return_user_params, get_root_directory
from src.packages.ZKPs.Schnorr import verify_proof

SIZE = 2048
PORT = 9999
ADDRESS = ('localhost', PORT)
root_directory = get_root_directory()
current_dir = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(root_directory,'population.json')
auth_path = os.path.join(current_dir,"auth_params.json")
votes_directory = os.path.join(get_root_directory(), "vote_data")


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(ADDRESS)

# Function for artificially generating a person in ID scheme.
def register_user (name):
    file_path = PATH
    c = MulElGamal(SIZE)
    c.generate_params()
    c.generate_keys()

    entry = {
        "NAME": name,
        "PUB_KEY": int_to_base64(c.pub_key),
        "PRIV_KEY": int_to_base64(c.priv_key),
        "MODULUS": int_to_base64(c.modulus),
        "GENERATOR": int_to_base64(c.generator),
    }
    
    json_data = read_from_json(file_path)
    json_data.append(entry)

    write_to_json(file_path, json_data)


def search_user(name, pub_key, path):
    
        data = read_from_json(path)
        for index, entry in enumerate(data):
            if entry.get("NAME") == name and entry.get("PUB_KEY") == pub_key:
                return index
        
        return -1  # Return -1 if no match is found

def create_voter_file(voter_id, index_in_population):
    path = os.path.join(votes_directory,f"voter_{voter_id}.json")
    if os.path.exists(path):
        return False
    
    data = read_from_json(PATH)[index_in_population]
    
    
    entry = {
        "NAME": voter_id,
        "PUB_KEY": data["PUB_KEY"],
        "MODULUS": data["MODULUS"],
        "GENERATOR": data["GENERATOR"]
    }

    data = read_from_json(path)
    data.append(entry)
    write_to_json(path, data)


    

def handle_client(client_socket, address):
    send_msg(client_socket, "Welcome! Please insert ID card into card reader for authentication.")
    
    connected = True
    while connected:

        if(get_socket_msg == False):
            break
        else:
            client_message = get_socket_msg(client_socket)

        client_message_obj = pickle.loads(client_message)
        
        name = client_message_obj[0]
        pub_key = client_message_obj[1]

        user_index = search_user(name, pub_key, PATH)

        if user_index != -1:
            send_msg(client_socket, "OK")
            client_message = get_socket_msg(client_socket)
            zk_proof = pickle.loads(client_message)

            params = return_user_params(user_index, PATH)
            modulus, generator, pub_key = params[0], params[1], params[2]
            q = (modulus-1) >> 1

            proof_verificaiton = verify_proof(modulus, q, generator, pub_key, zk_proof[0], zk_proof[1])
            
            if proof_verificaiton is True and create_voter_file(name, user_index) is not False:
                send_msg(client_socket, "Succesfully authenticated.")
                data = read_from_json(auth_path)
                print(data)
                for entry in data:
                    if entry["AUTH_NO"] == 1:
                        first_auth_port = entry["PORT"]
                send_msg(client_socket, str(first_auth_port))



            else:
                if proof_verificaiton is False:
                    print(1)
                    send_msg(client_socket, "Incorrect proof. Try again.")

                if create_voter_file(name, pub_key) is False:
                    print(2)
                    send_msg(client_socket, "Only 1 vote per person!.")
            

        else:
            send_msg(client_socket, "No public key associated with this name.\nClosing connection.")

        connected = False  # Exit the loop after processing one message  


    client_socket.close()
    print(f"Closed connection from {address}.")


def start():
    server.listen()
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target = handle_client, args = (conn, addr))
        thread.start()
        print("new thread started")


start()

        





    

