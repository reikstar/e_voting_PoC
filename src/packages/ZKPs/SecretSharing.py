from secrets import randbelow
from src.packages.math.mod_polynomial import Modular_Polynomial
from src.packages.math.mod_expo import base_k_exp
from src.packages.AsymmetricCiphers.ElGamal import MulElGamal
from src.packages.Utils.utils import fiat_shamir

K = 3

import gmpy2 as gmp
class SecretSharing:
    def __init__(self, p, q, alfa, beta):
        self.p = p
        self.q = q
        self.alfa = alfa
        self.beta = beta

    def distribute_secret(self, participants_key, threshold, secret):
        participants_number = len(participants_key)

        coefficients = [randbelow(self.q) for _ in range(threshold - 1)] #t-1 coefficients.
        coefficients.append(secret) #smallest order coefficient is the secret.
        poly = Modular_Polynomial(coefficients, self.q)

        coefficient_commitments = []  #starting from the highest order
        for coeff in coefficients:
            coefficient_commitments.append(base_k_exp(self.alfa, coeff, self.p, K))
        
        encryptions = [] #shares encrypted with key for user 1,2....n.
        for participant_index, key in enumerate(participants_key):
            encryptions.append(base_k_exp(key, poly(participant_index + 1), self.p, K))

        poly_from_commitment = []
        for i in range(participants_number):
            X_i = 1
            exp = threshold - 1
            for j in range(threshold):
                C_j = base_k_exp(coefficient_commitments[j], pow(i+1, exp), self.p, K)
                X_i = gmp.f_mod(gmp.mul(X_i, C_j), self.p)
                exp -= 1
            poly_from_commitment.append(X_i)

        return(coefficient_commitments, encryptions, poly_from_commitment, poly)
    
c = MulElGamal(16)
c.generate_params()     
            
ss = SecretSharing(c.modulus, c.q, 4, c.generator)

c.generate_keys()
pair1 = (c.pub_key, c.priv_key)
c.generate_keys()
pair2 = (c.pub_key, c.priv_key)
c.generate_keys()
pair3 = (c.pub_key, c.priv_key)

shares = ss.distribute_secret([pair1[0], pair2[0], pair3[0]], 2, 12)

encryptions = shares[1]
p_comms = shares[2]
poly = shares[3]

def dlog_eq(g1, h1, g2, h2, p, q, w):
    s = randbelow(q)
    commitments = []
    commitments.append(int(base_k_exp(g1, s, p, K)))
    commitments.append(int(base_k_exp(g2, s, p, K)))
    hash_value = fiat_shamir(g1, h1, g2, h2, p, q)
    challenge = gmp.f_mod(hash_value, q)
    prod = gmp.f_mod(gmp.mul(w, challenge), q)
    response = gmp.f_mod(prod + s, q)


    return (commitments, response)

def dlog_verify(g1, h1, g2, h2, p, q, commitments, response):
    hash_value = fiat_shamir(g1, h1, g2, h2, p, q)
    challenge = gmp.f_mod(hash_value, q)
    first_eq = gmp.f_mod(gmp.mul(commitments[0], base_k_exp(h1, challenge, p, K)), p)
    second_eq = gmp.f_mod(gmp.mul(commitments[1], base_k_exp(h2, challenge, p, K)), p)
    

    if base_k_exp(g1,response,p,K) != first_eq:
        return False
    
    if base_k_exp(g2,response,p,K) != second_eq:
        return False
    
    return True


prf = dlog_eq(ss.alfa, p_comms[0], pair1[0],encryptions[0], ss.p, ss.q, poly(1))
print(dlog_verify(ss.alfa, p_comms[0], pair1[0],encryptions[0], ss.p, ss.q,prf[0],prf[1]))