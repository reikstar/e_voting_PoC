from packages.math.prime import getSafePrime, jacobi_symbol
from packages.math.mod_expo import base_k_exp
from secrets import randbits
import gmpy2 as gmp
class ElGamalBase:
    def __init__(self, bits, predefined_group=False):
        self.bits = bits
        self.predefined_group = predefined_group
        self.modulus = None
        self.generator = None

    def generate_keys(self):
        if self.modulus is None or self.generator is None:
            raise AttributeError("Group parameters must be instantiated first.")
        
        self.priv_key = randbits(self.bits-1)
        self.pub_key = base_k_exp(self.generator, self.priv_key, self.modulus, 3)

    def generate_params(self, group_params=None):

        if self.predefined_group is False:
            self.modulus = getSafePrime(self.bits)
            
            # We check if 2 is quadratic residue so it can generate
            # the subgroup of order (modulus-1)/2.
            if jacobi_symbol(2, self.modulus) == 1:
                self.generator = 2
            else:
                self.generator = self.modulus-2

        elif group_params is not None:
            self.modulus = group_params[0]
            self.generator = group_params[1]

        else:
            raise AttributeError("Group parameters must be of tipe (x,y) where x is modulus and y is generator")
        

x = ElGamalBase(1000)
x.generate_params()
x.generate_keys()
print(x.priv_key)
print(x.pub_key)




            

            
            

        


