from secrets import randbelow
from src.packages.math.mod_expo import base_k_exp
from src.packages.Utils.utils import fiat_shamir, get_str_val, invert_ciphertext
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
    :param other_info: Extra info for Fiat-Shamir transformatioan (timestamp,id...etc).

    :return: A tuple containing the commitment and response.

    """

    rnd_value = randbelow(q)
    commitment = []

    str_val = get_str_val(other_info)

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
    :param commitment: Commitment obtained from first return value of decryption_proof()
    :param response: Response obtained from second return value of decryption_proof()
    :param plaintext: Encoded plaintext.
    :param ciphertext: Tuple of type (c1, c2) representing ciphertext.
    :param other_info: Extra info for Fiat-Shamir transformatioan (timestamp,id...etc).

    :return: A boolean value: True for valid proof, false otherwise.

    """

    str_val = get_str_val(other_info)

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
    """
    Designated verifier re-encryption proof. Given a ciphertext, a re-encryption
    of it and the public key of the verifier, it creates a proof that can be validated
    only by the verifier, without revealing the re-encryption factor.

    :param p: Group modulus.
    :param q: Subgroup order.
    :param generator: Primitive root of order q.
    :param verifier_pub_key: Verifier's public key.
    :param pub_key: pub_key of the form generator^x mod p.
    :param r_enc_factor: The value that the ciphertext is re-encrypted with.
    :param ciphertext: Tuple of type (c1, c2) representing ciphertext.
    :param r_enc_ciphertext: Tuple of type (c1, c2) representing re-encryption of ciphertext with r_enc_factor.
    :param other_info: Extra info for Fiat-Shamir transformatioan (timestamp,id...etc).

    :return: A tuple containing the commitment and response.

    """
    str_val = get_str_val(other_info)

    rand_values = [randbelow(q) for _ in range(3)]  # d,w,r
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
    """
    Verify a proof from re_encyption_proof.

    :param p: Group modulus.
    :param q: Subgroup order.
    :param generator: Primitive root of order q.
    :param verifier_pub_key: Verifier's public key.
    :param pub_key: pub_key of the form generator^x mod p.
    :param commitment: Commitment obtained from first return value of decryption_proof()
    :param response: Response obtained from second return value of decryption_proof()
    :param ciphertext: Tuple of type (c1, c2) representing ciphertext.
    :param r_enc_ciphertext: Tuple of type (c1, c2) representing re-encryption of ciphertext.
    :param other_info: Extra info for Fiat-Shamir transformatioan (timestamp,id...etc).

    :return: A boolean value: True for valid proof, false otherwise.

    """
    str_val = get_str_val(other_info)

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
    inv_ciphertext = invert_ciphertext(ciphertext, p)

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
        return False

    left_side = base_k_exp(generator, response[2], p, K)
    frac = gmp.f_mod(gmp.mul(r_enc_ciphertext[0], inv_ciphertext[0]), p)
    exponent = gmp.f_mod(challenge + response[0], q)

    right_side = gmp.f_mod(gmp.mul(commitment[0], base_k_exp(frac, exponent, p, K)), p)

    # Second equality.
    if left_side != right_side:
        return False

    left_side = base_k_exp(pub_key, response[2], p, K)
    frac = gmp.f_mod(gmp.mul(r_enc_ciphertext[1], inv_ciphertext[1]), p)

    right_side = gmp.f_mod(gmp.mul(commitment[1], base_k_exp(frac, exponent, p, K)), p)

    # Third equality.
    if left_side != right_side:
        return False

    return True


def re_encryption_or_proof(
    p,
    q,
    generator,
    pub_key,
    ciphertext,
    r_enc_index,
    r_enc_factor,
    encryption_list,
    other_info=None,
):
    """
    Generate an OR-proof for verifiable re-encryption. Given a ciphertext, a list
    of encryptions and the index of the re-encryption in the list, function provides
    a proof that in the list there exists one re-encryption of the ciphertext without 
    specifying which one.

    :param p: Group modulus.
    :param q: Subgroup order.
    :param generator: Primitive root of order q.
    :param pub_key: pub_key of the form generator^x mod p.
    :param ciphertext: Tuple of type (c1, c2) representing ciphertext.
    :param r_enc_index: Index indicating the position of the re-encryption in list.
    :param r_enc_factor: The value that the ciphertext is re-encrypted with.
    :param encryption_list: List of ciphertexts.
    :param other_info: Extra info for Fiat-Shamir transformatioan (timestamp,id...etc).

    :return: A tuple containing the commitment and response.
    
    """
    str_val = get_str_val(other_info)

    rnd_list1 = [randbelow(q) for i in range(len(encryption_list))]  # d
    rnd_list2 = [randbelow(q) for i in range(len(encryption_list))]  # r
    inv_ciphertext = invert_ciphertext(ciphertext, p)

    chameleon_value = gmp.f_mod(
        gmp.mul(r_enc_factor, rnd_list1[r_enc_index]) + rnd_list2[r_enc_index], q
    )  # w

    commitment = []
    for i in range(len(encryption_list)):
        frac1 = gmp.f_mod(gmp.mul(encryption_list[i][0], inv_ciphertext[0]), p)
        frac2 = gmp.f_mod(gmp.mul(encryption_list[i][1], inv_ciphertext[1]), p)

        frac1 = base_k_exp(frac1, rnd_list1[i], p, K)
        frac2 = base_k_exp(frac2, rnd_list1[i], p, K)

        a = gmp.f_mod(gmp.mul(frac1, base_k_exp(generator, rnd_list2[i], p, K)), p)
        b = gmp.f_mod(gmp.mul(frac2, base_k_exp(pub_key, rnd_list2[i], p, K)), p)

        commitment.append((a, b))

    hash_value = fiat_shamir(
        p, q, generator, pub_key, ciphertext, encryption_list, commitment, str_val
    )
    challenge = gmp.f_mod(hash_value, q)

    commitment_sum = 0
    for i in range(len(rnd_list1)):
        if i == r_enc_index:
            continue
        commitment_sum += rnd_list1[i]

    rnd_list1[r_enc_index] = int(gmp.f_mod(challenge - commitment_sum, q))  # updated d_t
    rnd_list2[r_enc_index] = int(gmp.f_mod(
        chameleon_value - gmp.mul(r_enc_factor, rnd_list1[r_enc_index]), q
    ))  # updated r_t

    response = (rnd_list1, rnd_list2)

    return (commitment, response)


def re_encryption_or_verify(
    p,
    q,
    generator,
    pub_key,
    ciphertext,
    encryption_list,
    commitment,
    response,
    other_info=None,
):
    """
    Verify a proof from re_encyption_or_proof.

    :param p: Group modulus.
    :param q: Subgroup order.
    :param generator: Primitive root of order q.
    :param pub_key: pub_key of the form generator^x mod p.
    :param ciphertext: Tuple of type (c1, c2) representing ciphertext.
    :param encryption_list: List of ciphertexts.
    :param commitment: Commitment obtained from first return value of decryption_proof()
    :param response: Response obtained from second return value of decryption_proof()
    :param other_info: Extra info for Fiat-Shamir transformatioan (timestamp,id...etc).

    :return: A boolean value: True for valid proof, false otherwise.

    """    
    str_val = get_str_val(other_info)
    inv_ciphertext = invert_ciphertext(ciphertext, p)

    hash_value = fiat_shamir(
        p, q, generator, pub_key, ciphertext, encryption_list, commitment, str_val
    )
    challenge = gmp.f_mod(hash_value, q)

    check_sum = 0
    # Sum of d's
    for value in response[0]:
        check_sum += value

    check_sum = gmp.f_mod(check_sum, q)

    # First equality.
    if challenge != check_sum:
        return False

    for i in range(len(encryption_list)):
        frac1 = gmp.f_mod(gmp.mul(encryption_list[i][0], inv_ciphertext[0]), p)
        frac2 = gmp.f_mod(gmp.mul(encryption_list[i][1], inv_ciphertext[1]), p)

        frac1 = base_k_exp(frac1, response[0][i], p, K)
        frac2 = base_k_exp(frac2, response[0][i], p, K)

        a = gmp.f_mod(gmp.mul(frac1, base_k_exp(generator, response[1][i], p, K)), p)
        b = gmp.f_mod(gmp.mul(frac2, base_k_exp(pub_key, response[1][i], p, K)), p)

        # 2nd equailty.
        if commitment[i][0] != a:
            return False

        # 3rd equality.
        if commitment[i][1] != b:
            return False

    return True