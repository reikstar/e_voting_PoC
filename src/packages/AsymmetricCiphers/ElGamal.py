
from packages.math.prime import getSafePrime, jacobi_symbol
from packages.math.mod_expo import base_k_exp
from secrets import randbits
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
        self.bits = bits
        self.predefined_group = predefined_group
        self.modulus = None
        self.generator = None
        self.__priv_key = None
        self.__pub_key = None

    def generate_keys(self):
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
            if len(group_params) != 2:
                raise AttributeError("Group parameters must be of tipe (x,y) where x is modulus and y is generator")
            self.modulus = group_params[0]
            self.generator = group_params[1]

        else:
            raise AttributeError("Predefined group was used but not given group parameters.")
        
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
        rnd_value = randbits(self.bits-1)
        
        c1 = base_k_exp(self.generator, rnd_value, self.modulus, K)
        c2 = gmp.f_mod(gmp.mul(encoded_val, base_k_exp(key, rnd_value, self.modulus, K)), self.modulus)

        return (int(c1), int(c2))

    def decrypt(self, ciphertext):

        c1, c2 = ciphertext[0], ciphertext[1]
        if c2 > self.modulus - 1 or c1 > self.modulus - 1:
            raise AttributeError("Invalid ciphertext, parameters bigger than modulus.")
        q = (self.modulus-1) >> 1

        decryption_val = gmp.invert(base_k_exp(c1, self.priv_key, self.modulus, K), self.modulus)
        enccoded_val =  gmp.f_mod(gmp.mul(c2, decryption_val), self.modulus)
        plaintext = base_k_exp(enccoded_val, (q+1) >> 1, self.modulus, K)

        return plaintext if plaintext <= q else self.modulus - plaintext
    

x = MulElGamal(151)
x.generate_params()
x.generate_keys()

a = x.encrypt(5123, x.pub_key)
print(x.decrypt(a))

        










    




            
            

        


