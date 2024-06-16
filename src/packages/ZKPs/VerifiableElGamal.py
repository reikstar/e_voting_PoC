from secrets import randbelow
from src.packages.math.mod_expo import base_k_exp
from src.packages.Utils.utils import fiat_shamir
import gmpy2 as gmp

K = 3  # Base for base_k_exp.


def decryption_proof(
    p, q, generator, priv_key, pub_key, plaintext, ciphertext, other_info=None
):
    """
    Generate a proof such that given a plaintext it was obtained from the specific ciphertext
    without revealing the private key.

    !NOTICE!: Plaintext argument MUST be given as the encoded form. For MulElGamal it will be
    of the form of (plaintext)^2 mod p and for AddElGamal beta^plaintext mod p.

    :param p: Group modulus.
    :param q: Subgroup order.
    :param generator: Primitive root of order q.
    :param priv_key: private key (x \in Z_q)
    :param pub_key: pub_key of the form generator^x mod p.
    :param plaintext: Encoded plaintext.
    :param ciphertext: Tuple of type (c1, c2) representing ciphertext.
    :other_info: Extra info for Fiat-Shamir transformatioan (timestamp,id...etc).

    :return: A tuple containing the commitment and response.

    """

    rnd_value = randbelow(q)
    commitment = []

    if other_info is not None:
        str_val = str(other_info)
    else:
        str_val = ""

    commitment.append(int(base_k_exp(generator, rnd_value, p, K)))
    commitment.append(int(base_k_exp(ciphertext[0], rnd_value, p, K)))

    hash_value = fiat_shamir(
        p, q, generator, pub_key, plaintext, ciphertext, commitment, str_val
    )
    challenge = gmp.f_mod(hash_value, q)

    prod = gmp.f_mod(gmp.mul(challenge, priv_key), q)
    response = gmp.f_mod(rnd_value + prod, q)

    return (commitment, response)


def decryption_verify(
    p,
    q,
    generator,
    pub_key,
    commitment,
    response,
    plaintext,
    ciphertext,
    other_info=None,
):
    """
    Verify a proof obtained from decryption_proof.

    !NOTICE!: Plaintext argument MUST be given as the encoded form. For MulElGamal it will be
    of the form of (plaintext)^2 mod p and for AddElGamal beta^plaintext mod p.

    :param p: Group modulus.
    :param q: Subgroup order.
    :param generator: Primitive root of order q.
    :param pub_key: pub_key of the form generator^x mod p.
    :param plaintext: Encoded plaintext.
    :param ciphertext: Tuple of type (c1, c2) representing ciphertext.
    :other_info: Extra info for Fiat-Shamir transformatioan (timestamp,id...etc).

    :return: A boolean value: True for valid proof, false otherwise.

    """

    if other_info is not None:
        str_val = str(other_info)
    else:
        str_val = ""

    hash_value = fiat_shamir(
        p, q, generator, pub_key, plaintext, ciphertext, commitment, str_val
    )
    challenge = gmp.f_mod(hash_value, q)

    # First equality.
    left1 = base_k_exp(generator, response, p, K)
    right1 = gmp.f_mod(gmp.mul(commitment[0], base_k_exp(pub_key, challenge, p, K)), p)
    if left1 != right1:
        return False

    inv_plaintext = gmp.invert(plaintext, p)
    frac = gmp.f_mod(gmp.mul(ciphertext[1], inv_plaintext), p)  # G^x = m * y^r / m

    # Second equality.
    left2 = base_k_exp(ciphertext[0], response, p, K)
    right2 = gmp.f_mod(gmp.mul(commitment[1], base_k_exp(frac, challenge, p, K)), p)
    if left2 != right2:
        return False

    return True
