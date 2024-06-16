from secrets import randbelow
from src.packages.Utils.utils import fiat_shamir
from src.packages.math.mod_expo import base_k_exp
import gmpy2 as gmp

K = 3  # base_k_exp base


def generate_proof(p, q, generator, priv_key, pub_key, other_info=None):
    """
    Produce a Non-Interactive Zero-Knowledge proof for priv_key.
    Group modulus is p = 2q +1, with generator being primitive root of order q.
    other_info parmeter can be used for extra attributes, s.a timestamp or ID's.

    :param p: Group modulus.
    :param q: Subgroup order.
    :param generator: Primitive root of order q.
    :param priv_key: private key (x \in Z_q)
    :param pub_key: pub_key of the form generator^x mod p.
    :other_info: Extra info for Fiat-Shamir transformatioan (timestamp,id...etc).

    :return: A tuple containing the commitment and response.
    """

    rnd_value = randbelow(q)
    commitment = base_k_exp(generator, rnd_value, p, K)

    if other_info is not None:
        str_val = str(other_info)
    else:
        str_val = ""

    hash_value = fiat_shamir(p, q, generator, pub_key, commitment, str_val)
    challenge = gmp.f_mod(hash_value, q)

    prod = gmp.f_mod(gmp.mul(challenge, priv_key), q)
    response = gmp.f_mod(rnd_value + prod, q)

    return (int(commitment), int(response))


def verify_proof(p, q, generator, pub_key, commitment, response, other_info=None):
    """
    Verify a proof produced by generate_proof with the same parameters.

    :return: A boolean value: True for valid proof, false otherwise.
    """

    if other_info is not None:
        str_val = str(other_info)
    else:
        str_val = ""

    hash_value = fiat_shamir(p, q, generator, pub_key, commitment, str_val)
    challenge = gmp.f_mod(hash_value, q)

    if base_k_exp(generator, response, p, K) == gmp.f_mod(
        gmp.mul(commitment, base_k_exp(pub_key, challenge, p, K)), p
    ):
        return True
    else:
        return False
