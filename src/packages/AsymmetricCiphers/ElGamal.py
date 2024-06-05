from packages.math.prime import getSafePrime
class ElGamalBase:
    def __init__(self, bits, predefined_group=False):
        self.bits = bits
        self.predefined_group = predefined_group

    def generate_params(self, bits, predefined_group):
        print("heyk")


print(getSafePrime(100))