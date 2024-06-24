import os
from src.packages.Utils.utils import read_from_json, write_to_json, int_to_base64
from src.packages.AsymmetricCiphers.ElGamal import AddElGamal
import socket
import threading
import pickle
import json
from src.packages.Utils.network_utils import get_socket_msg, send_msg
from src.packages.Utils.utils import return_user_params, get_root_directory
from src.packages.ZKPs.Schnorr import verify_proof
SIZE = 2048
PORT = 9999
ADDRESS = ('localhost', PORT)
HEADERSIZE = 30
root_directory = get_root_directory()
PATH = os.path.join(root_directory,'population.json')


# Function for artificially generating a person in ID scheme.
def register_user (name):
    file_path = PATH
    c = AddElGamal(SIZE)
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
    
    with open(path, "r") as json_file:
        data = json.load(json_file)
        
        for index, entry in enumerate(data):
            if entry.get("NAME") == name and entry.get("PUB_KEY") == pub_key:
                return index
        
        return -1  # Return -1 if no match is found
    

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
            
            if proof_verificaiton is True:
                send_msg(client_socket, "Succesfully authenticated.")
            else:
                send_msg(client_socket, "Incorrect proof. Try again.")
            

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

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(ADDRESS)
#register_user("andrei")
start()

    
        





    

