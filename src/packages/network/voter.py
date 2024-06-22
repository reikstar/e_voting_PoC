import pickle
import socket
import os
from src.packages.AsymmetricCiphers.ElGamal import AddElGamal
from src.packages.ZKPs.Schnorr import generate_proof
from src.packages.Utils.network_utils import get_socket_msg, send_msg
from src.packages.Utils.utils import base64_to_int, int_to_base64, read_from_json
HEADERSIZE = 30
SIZE = 1000

current_dir = os.path.dirname(os.path.abspath(__file__))
filepath = os.path.join(current_dir, 'id_card.json')

c = AddElGamal(SIZE, True)
beta = 4

#Read data from id_card and set group parameters.
data = read_from_json(filepath)
pub_k = base64_to_int(data.get("PUB_KEY"))
priv_key = base64_to_int(data.get("PRIV_KEY"))
modulus = base64_to_int(data.get("MODULUS"))
generator = base64_to_int(data.get("GENERATOR"))

c.generate_params((modulus,generator,beta))
c.set_keys(pub_k, priv_key)


def authentication(name, pub_key, priv_key, p, q, generator):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.connect(('localhost', 9999))
        
        not_authenticated = True
        data = (name, int_to_base64(pub_key))
        
        while not_authenticated:
            server_msg = get_socket_msg(server_socket).decode('utf-8')
            print(server_msg)
            
            if not_authenticated:
                msg = pickle.dumps(data)
                send_msg(server_socket, msg)

                server_msg = get_socket_msg(server_socket).decode('utf-8')

                if server_msg == "OK":
                    zk_proof = generate_proof(p, q, generator, priv_key, pub_key)

                    msg = pickle.dumps(zk_proof)
                    send_msg(server_socket, msg)

                    server_msg = get_socket_msg(server_socket).decode('utf-8')
                    print(server_msg)

                else:
                    print(server_msg)

                not_authenticated = False  # Update authentication state

    except ConnectionError as e:
        print(f"Connection error: {e}")


authentication("andrei",c.pub_key, c.priv_key, c.modulus, c.q, c.generator)

