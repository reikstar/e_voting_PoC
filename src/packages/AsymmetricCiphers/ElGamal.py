from packages.math.prime import getSafePrime, jacobi_symbol
from packages.math.mod_expo import base_k_exp
from packages.Utils.utils import get_rfc_group
from secrets import randbits, randbelow
import gmpy2 as gmp

K = 3

class ElGamalBase:
    
    def __init__(self, bits, predefined_group=False):
        """
        Initialize the ElGamalBase class with the given bit length and group type.
        Private and public key are private attributes.

        :param bits: The bit length for modulus.
        :param predefined_group: Indicator if a predefined group is used.
        """
        
        if type(self) is ElGamalBase:
            raise TypeError("Class not instantiable.")

        self.bits = bits
        self.predefined_group = predefined_group
        self.modulus = None
        self.q = None
        self.generator = None
        self.__priv_key = None
        self.__pub_key = None

    def generate_keys(self):
        """
        Generate random private and public key.

        """
        if self.modulus is None or self.generator is None:
            raise AttributeError("Group parameters must be instantiated first.")
        
        self.__priv_key = randbits(self.bits-1)
        self.__pub_key = base_k_exp(self.generator, self.__priv_key, self.modulus, K)

    def set_keys(self,public,private):
        self.__pub_key = public
        self.__priv_key = private

    def generate_params(self, group_params=None):
        """
        Generate the group parameters (modulus and generator) or set them if provided.
        If not provided, the modulus will have the form of p = 2q + 1, where p and q
        are primes. The generator will have the order of q.
        
        :param group_params: Tuple containing the modulus and generator.
        """

        if self.predefined_group is False:
            self.modulus = getSafePrime(self.bits)
            
            # We check if 2 is quadratic residue so it can generate
            # the subgroup of order (modulus-1)/2.
            if jacobi_symbol(2, self.modulus) == 1:
                self.generator = 2
            else:
                self.generator = self.modulus-2

        elif group_params is not None:
            self._validate_and_set_params(group_params)

        else:
            raise AttributeError("Predefined group was used but not given group parameters.")

        self.q = (self.modulus - 1) >> 1

    def _validate_and_set_params(self, group_params):
        if len(group_params) != 2:
            raise AttributeError("Group parameters must be of type (x, y) where x is modulus and y is generator.")
        self.modulus = group_params[0]
        self.generator = group_params[1]

    def re_encrypt(self, ciphertext, rnd_value, key):
        """
        Re-encrypt a ciphertext with a new random value.

        :param ciphertext: Tuple containing (c1, c2) components of the ciphertext.
        :param rnd_value: The new random value for re-encryption.
        :param key: The public key for encryption.
        
        :return: Tuple containing the re-encrypted (c1, c2).

        """

        c1, c2 = ciphertext[0], ciphertext[1]
        if c2 > self.modulus - 1 or c1 > self.modulus - 1:
            raise AttributeError("Invalid ciphertext, parameters bigger than modulus.")
        if rnd_value > self.q:
            raise AttributeError("Invalid random value, must be smaller than q.")
    
        c1_val = base_k_exp(self.generator, rnd_value, self.modulus, K)
        c2_val = base_k_exp(key, rnd_value, self.modulus, K)

        c1 = gmp.f_mod(gmp.mul(c1, c1_val), self.modulus)
        c2 = gmp.f_mod(gmp.mul(c2, c2_val), self.modulus)

        return (int(c1), int(c2))
    
    def homomorphic_mul(self, ciphertext_a, ciphertext_b):
        """
        Perform homomorphic operation of two ciphertexts.

        :param ciphertext_a: Tuple containing (c1, c2) components of the first ciphertext.
        :param ciphertext_b: Tuple containing (c1, c2) components of the second ciphertext.
        
        :return: Tuple containing the resulting (c1, c2) after operation.
        """

        if ciphertext_a[0] >= self.modulus or ciphertext_a[1] >= self.modulus:
            raise AttributeError("Invalid ciphertext, parameters bigger than modulus.")
        
        if ciphertext_b[0] >= self.modulus or ciphertext_b[1] >= self.modulus:
            raise AttributeError("Invalid ciphertext, parameters bigger than modulus.")
        
        c1 = gmp.f_mod(gmp.mul(ciphertext_a[0], ciphertext_b[0]), self.modulus)
        c2 = gmp.f_mod(gmp.mul(ciphertext_a[1], ciphertext_b[1]), self.modulus)

        return (int(c1), int(c2))
     
    @property
    def priv_key(self):
        return self.__priv_key
    
    @property
    def pub_key(self):
        return self.__pub_key


class MulElGamal(ElGamalBase):

    def __init__(self, bits, predefined_group=False):
        super().__init__(bits, predefined_group)

    def encrypt(self, plaintext, key):
        if plaintext > self.modulus-1:
            raise AttributeError("Invalid plaintext, parameter bigger than modulus.")
        
        encoded_val = gmp.f_mod(gmp.square(plaintext), self.modulus)
        rnd_value = randbelow(self.q + 1)
        
        c1 = base_k_exp(self.generator, rnd_value, self.modulus, K)
        c2 = gmp.f_mod(gmp.mul(encoded_val, base_k_exp(key, rnd_value, self.modulus, K)), self.modulus)

        return (int(c1), int(c2))

    def decrypt(self, ciphertext):
        """
        Decrypt a ciphertext with object's private key.

        :param ciphertext: Tuple containing (c1, c2) components of ciphertext.

        :return: Decrypted ciphertext.
        """

        c1, c2 = ciphertext[0], ciphertext[1]
        if c2 > self.modulus - 1 or c1 > self.modulus - 1:
            raise AttributeError("Invalid ciphertext, parameters bigger than modulus.")
        
        decryption_val = gmp.invert(base_k_exp(c1, self.priv_key, self.modulus, K), self.modulus)
        encoded_val =  gmp.f_mod(gmp.mul(c2, decryption_val), self.modulus)
        plaintext = base_k_exp(encoded_val, (self.q+1) >> 1, self.modulus, K)

        return plaintext if plaintext <= self.q else self.modulus - plaintext


class AddElGamal(ElGamalBase):

    def __init__(self, bits, predefined_group=False):
        super().__init__(bits, predefined_group)
        self.beta = None

    def generate_params(self, group_params=None):
        super().generate_params(group_params)

        if group_params is None:
            self.beta = 4 # 2^2 is a quadratic residue, so it will generate subgroup of order Q.

    def _validate_and_set_params(self, group_params):
        if len(group_params) != 3:
            raise AttributeError("Group parameters must be of type (x, y, z) where x is modulus and y,z are generators.")
        self.modulus = group_params[0]
        self.generator = group_params[1]
        self.beta = group_params[2]

    def encrypt(self, plaintext, key):
        if plaintext >= self.q:
            raise AttributeError("Invalid plaintext. Parmeter must be smaller than q")
        
        rnd_value = randbelow(self.q + 1)
        
        encoded_val = base_k_exp(self.beta, plaintext, self.modulus, K)
        c1 = base_k_exp(self.generator, rnd_value, self.modulus, K)
        c2 = gmp.f_mod(gmp.mul(encoded_val, base_k_exp(key, rnd_value, self.modulus, K)), self.modulus)

        return (int(c1), int(c2))
    
    def decrypt(self, ciphertext):
        """
        Decrypt a ciphertext with object's private key. Note that this is slower than
        classic ElGamal, because it's required to find the discrete logarithm of beta^m.

        :param ciphertext: Tuple containing (c1, c2) components of ciphertext.

        :return: Decrypted ciphertext.
        """
        c1, c2 = ciphertext[0], ciphertext[1]
        if c2 > self.modulus - 1 or c1 > self.modulus - 1:
            raise AttributeError("Invalid ciphertext, parameters bigger than modulus.")
        
        decryption_val = gmp.invert(base_k_exp(c1, self.priv_key, self.modulus, K), self.modulus)
        encoded_val =  gmp.f_mod(gmp.mul(c2, decryption_val), self.modulus)
        
        product = 1
        for i in range(1, self.q + 1):
            product = gmp.f_mod(gmp.mul(product, self.beta),self.modulus)
            if gmp.f_mod(product, self.modulus) == encoded_val:
                return i
        








        










    




            
            

        


