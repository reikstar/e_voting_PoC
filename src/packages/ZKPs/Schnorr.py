from hashlib import sha512
from secrets import randbelow
from packages.math.mod_expo import base_k_exp
from packages.AsymmetricCiphers.ElGamal import MulElGamal
import gmpy2 as gmp

K = 3 #base_k_exp base


def generate_proof(p, q, generator, priv_key, pub_key, other_info = None):

    h = sha512()
    rnd_value = randbelow(q)
    commitment = base_k_exp(generator, rnd_value, p, K)
    
    if other_info is not None:
        str_val = str(other_info)
    else:
        str_val = ""

    hash_input = str(p) + str(q) + str(generator) + str(pub_key) + str(commitment) + str_val
    h.update(hash_input.encode())
   
    challenge = gmp.f_mod(int(h.hexdigest(), 16), q)
    
    prod = gmp.f_mod(gmp.mul(challenge, priv_key), q)
    response = gmp.f_mod(rnd_value + prod, q)

    return(int(commitment), int(response))


def verify_proof(p, q, generator, pub_key, commitment, response, other_info = None):

    h = sha512()

    if other_info is not None:
        str_val = str(other_info)
    else:
        str_val = ""

    hash_input = str(p) + str(q) + str(generator) + str(pub_key) + str(commitment) + str_val
    h.update(hash_input.encode())
   
    challenge = gmp.f_mod(int(h.hexdigest(), 16), q)

    if base_k_exp(generator, response, p, K) == gmp.f_mod(gmp.mul(commitment, base_k_exp(pub_key, challenge, p, K)), p):
        return True
    else:
        return False



