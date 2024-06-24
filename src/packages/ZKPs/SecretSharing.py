from secrets import randbelow
from src.packages.math.mod_polynomial import Modular_Polynomial
from src.packages.math.mod_expo import base_k_exp
from src.packages.AsymmetricCiphers.ElGamal import MulElGamal
from src.packages.Utils.utils import fiat_shamir

K = 3

import gmpy2 as gmp

def dlog_eq(g1, h1, g2, h2, p, q, w):
    """
    Generate a proof that log_g1(h1) = log_g2(h2), with the witness being w.

    :param g1: First log base.
    :param h1: First log upper value.
    :param g2: Second log base.
    :param h2: Second log upper value.
    :param p: Group modulus.
    :param q: Subgroup order.
    :param w: Witness.

    :return: A tuple containing the commitment and response.

    """
    s = randbelow(q)
    commitments = []

    commitments.append(int(base_k_exp(g1, s, p, K)))
    commitments.append(int(base_k_exp(g2, s, p, K)))

    hash_value = fiat_shamir(g1, h1, g2, h2, p, q)
    challenge = gmp.f_mod(hash_value, q)

    prod = gmp.f_mod(gmp.mul(w, challenge), q)
    response = int(gmp.f_mod(prod + s, q))

    return (commitments, response)

def dlog_verify(g1, h1, g2, h2, p, q, commitments, response):
    """
    Verify a proof from dlog_eq.
    :param g1: First log base.
    :param h1: First log upper value.
    :param g2: Second log base.
    :param h2: Second log upper value.
    :param p: Group modulus.
    :param q: Subgroup order.
    :param commitment: Commitment obtained from first return value of dlog_eq()
    :param response: Response obtained from second return value of dlog_eq()

    """
    hash_value = fiat_shamir(g1, h1, g2, h2, p, q)
    challenge = gmp.f_mod(hash_value, q)

    first_eq = gmp.f_mod(gmp.mul(commitments[0], base_k_exp(h1, challenge, p, K)), p)
    second_eq = gmp.f_mod(gmp.mul(commitments[1], base_k_exp(h2, challenge, p, K)), p)

    if base_k_exp(g1,response,p,K) != first_eq:
        return False
    
    if base_k_exp(g2,response,p,K) != second_eq:
        return False
    
    return True


class SecretSharing:
    def __init__(self, p, q, alfa, beta):
        self.p = p
        self.q = q
        self.alfa = alfa
        self.beta = beta

    def distribute_secret(self, participants_key, threshold, secret):
        participants_number = len(participants_key)

        # Generate polynomial coefficients and create the polynomial.
        coefficients = [randbelow(self.q) for _ in range(threshold - 1)] # t-1 coefficients.
        coefficients.append(secret) # Smallest order coefficient is the secret.
        poly = Modular_Polynomial(coefficients, self.q)

        # Starting from the highest order, we create commitment for each coeff.
        coefficient_commitments = []  
        for coeff in coefficients:
            coefficient_commitments.append(base_k_exp(self.alfa, coeff, self.p, K))

        # Shares encrypted with user's key for user 1,2....n.
        # The encryption has the form of a point on the polynomial as
        # (i, key^poly(i)).
        encryptions = [] 
        for participant_index, key in enumerate(participants_key):
            encryptions.append((participant_index, base_k_exp(key, poly(participant_index + 1), self.p, K)))

        # Calculate polynomial values from commitment and generate ZKP.
        poly_from_commitment = []
        zk_proofs = []

        for i in range(participants_number):
            X_i = 1
            exp = threshold - 1

            for j in range(threshold):
                C_j = base_k_exp(coefficient_commitments[j], pow(i+1, exp, self.q), self.p, K)
                X_i = gmp.f_mod(gmp.mul(X_i, C_j), self.p)
                exp -= 1

            poly_from_commitment.append(X_i)

            proof = dlog_eq(self.alfa, X_i, participants_key[i], encryptions[i][1], self.p, self.q, poly(i+1))
            zk_proofs.append(proof)


        return(coefficient_commitments, encryptions, poly_from_commitment, zk_proofs)
    
    def decrypt_and_share(self, share, pub_key, priv_key):
        decrypted_share = base_k_exp(share, gmp.invert(priv_key, self.q), self.p, K)
        
        proof = dlog_eq(self.beta, pub_key, decrypted_share, share, self.p, self.q, priv_key)
        
        return (decrypted_share,proof)
    
    def get_secret(self, shares):
        secret = 1

        for i in range(0, len(shares)):
            z = shares[i][1]

            numerator = 1
            denominator = 1
            
            for j in range(0, len(shares)):
                if shares[j][0] == shares[i][0]:
                    continue
                
                numerator = gmp.f_mod(gmp.mul(shares[j][0], numerator), self.q)
                denominator = gmp.f_mod(gmp.mul(gmp.f_mod(shares[j][0] - shares[i][0], self.q), denominator), self.q)

            exponent = int(gmp.f_mod(gmp.mul(numerator, gmp.invert(denominator, self.q)), self.q))
            exponentiation = base_k_exp(z, exponent, self.p, K)

            secret = gmp.f_mod(gmp.mul(secret, exponentiation), self.p)

        return secret

