from secrets import randbelow
from src.packages.AsymmetricCiphers.ElGamal import AddElGamal
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


def re_encyption_proof(
    p,
    q,
    generator,
    verifier_pub_key,
    pub_key,
    r_enc_factor,
    ciphertext,
    r_enc_ciphertext,
    other_info=None,
):
    if other_info is not None:
        str_val = str(other_info)
    else:
        str_val = ""

    rand_values = [randbelow(q) for i in range(3)]  # d,w,r
    commitment = []
    response = []

    commitment.append(base_k_exp(generator, rand_values[0], p, K))  # a
    commitment.append(base_k_exp(pub_key, rand_values[0], p, K))  # b
    commitment.append(
        gmp.f_mod(
            gmp.mul(
                base_k_exp(generator, rand_values[1], p, K),
                base_k_exp(verifier_pub_key, rand_values[2], p, K),
            ),
            p,
        )
    )  # s

    hash_value = fiat_shamir(
        p,
        q,
        generator,
        verifier_pub_key,
        pub_key,
        commitment,
        ciphertext,
        r_enc_ciphertext,
        str_val,
    )
    challenge = gmp.f_mod(hash_value, q)

    response.append(rand_values[1])  # w
    response.append(rand_values[2])  # r
    response.append(
        gmp.f_mod(rand_values[0] + gmp.mul(r_enc_factor, challenge + rand_values[1]), q)
    )  # t

    return (commitment, response)


def re_encyption_verify(
    p,
    q,
    generator,
    verifier_pub_key,
    pub_key,
    commitment,
    response,
    ciphertext,
    r_enc_ciphertext,
    other_info=None,
):
    if other_info is not None:
        str_val = str(other_info)
    else:
        str_val = ""

    hash_value = fiat_shamir(
        p,
        q,
        generator,
        verifier_pub_key,
        pub_key,
        commitment,
        ciphertext,
        r_enc_ciphertext,
        str_val,
    )
    challenge = gmp.f_mod(hash_value, q)

    inv_ciphertext = []
    for i in range(2):
        inv_ciphertext.append(gmp.invert(ciphertext[i], p))

    left_side = commitment[2]

    right_side = gmp.f_mod(
        gmp.mul(
            base_k_exp(generator, response[0], p, K),
            base_k_exp(verifier_pub_key, response[1], p, K),
        ),
        p,
    )
    # First equality.
    if left_side != right_side:
        print("first eq failed")
        return False

    left_side = base_k_exp(generator, response[2], p, K)
    frac = gmp.f_mod(gmp.mul(r_enc_ciphertext[0], inv_ciphertext[0]), p)
    exponent = gmp.f_mod(challenge + response[0], q)

    right_side = gmp.f_mod(gmp.mul(commitment[0], base_k_exp(frac, exponent, p, K)), p)

    # Second equality.
    if left_side != right_side:
        print("2nd eq failed")
        return False

    left_side = base_k_exp(pub_key, response[2], p, K)
    frac = gmp.f_mod(gmp.mul(r_enc_ciphertext[1], inv_ciphertext[1]), p)

    right_side = gmp.f_mod(gmp.mul(commitment[1], base_k_exp(frac, exponent, p, K)), p)

    # Third equality.
    if left_side != right_side:
        print("3rd eq failed")
        return False

    return True


