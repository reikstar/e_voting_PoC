from hashlib import sha512
from secrets import randbelow
from packages.math.mod_expo import base_k_exp
import gmpy2 as gmp
from packages.AsymmetricCiphers.ElGamal import AddElGamal

K = 3  # Base for base_k_exp.

def decryption_proof(p, q, generator, priv_key, pub_key, plaintext, ciphertext, other_info=None):
    h = sha512()
    rnd_value = randbelow(q)
    commitment = []
    
    commitment.append(int(base_k_exp(generator, rnd_value, p, K)))
    commitment.append(int(base_k_exp(ciphertext[0], rnd_value, p, K)))

    hash_input = str(p) + str(q) + str(generator) + str(pub_key) + str(plaintext) + str(ciphertext) + str(commitment) + str(other_info)
    h.update(hash_input.encode())

    challenge = gmp.f_mod(int(h.hexdigest(), 16), q)

    prod = gmp.f_mod(gmp.mul(challenge, priv_key), q)
    response = gmp.f_mod(rnd_value + prod, q)

    return (commitment, response)

def decryption_verify(p, q, generator, pub_key, commitment, response, plaintext, ciphertext, other_info=None):
    h = sha512()

    if other_info is not None:
        str_val = str(other_info)
    else:
        str_val = ""

    hash_input = str(p) + str(q) + str(generator) + str(pub_key) + str(plaintext) + str(ciphertext) + str(commitment) + str(other_info)
    h.update(hash_input.encode())

    challenge = gmp.f_mod(int(h.hexdigest(), 16), q)

    # First equality.
    left1 = base_k_exp(generator, response, p, K)
    right1 = gmp.f_mod(gmp.mul(commitment[0], base_k_exp(pub_key, challenge, p, K)), p)
    if left1 != right1:
        print(f"First check failed: {left1} != {right1}")
        print(1)
        return False
    
    inv_plaintext = gmp.invert(plaintext, p)
    frac = gmp.f_mod(gmp.mul(ciphertext[1], inv_plaintext), p)  # G^x = m * y^r / m 

    # Second equality.
    left2 = base_k_exp(ciphertext[0], response, p, K)
    right2 = gmp.f_mod(gmp.mul(commitment[1], base_k_exp(frac, challenge, p, K)), p)
    if left2 != right2:
        print(f"Second check failed: {left2} != {right2}")
        print(2)
        return False
    
    return True


x = AddElGamal(100)
x.generate_params()
x.generate_keys()
ciph = x.encrypt(12, x.pub_key)

b = decryption_proof(x.modulus, x.q, x.generator, x.priv_key, x.pub_key, 12, ciph)
print(decryption_verify(x.modulus, x.q, x.generator, x.pub_key, b[0], b[1], 12, ciph))
