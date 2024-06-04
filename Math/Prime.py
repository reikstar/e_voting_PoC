
from secrets import randbits
from Crypto.Random.random import randint
from PrimeSieve import prime_set # Sieve of first 10000 primes.
import gmpy2 as gmp


#This computes the jacobi_symbol for an odd number a,
#with the modulus n. Instead of using mod 2^k, we used
#bitwise operator &, s.t x mod 2^k is x & (2^k-1). 
def jacobi_symbol(a, n):
    if n < 0 or n & 1 == 0:
        raise ValueError("n must be positive and odd")
    
    n = gmp.mpz(n) 
    a = gmp.f_mod(a, n)
    result = 1

    while a != 0:
        while a & 1 == 0:
            a >>= 1
            if n & 7 in (3, 5):
                result = -result

        a, n = n, a  
        if a & 3 == 3 and n & 3 == 3:
            result = -result

        a = a % n

    return result if n == 1 else 0

#It generates a random n bits odd number,
#with most significant bit 1.
def odd_random(n):
    if n < 2:
        raise ValueError("n must be at least 2.")
    rnd_value = randbits(n - 2)
    
    #Construct the number with MSB and LSB set to 1.
    odd_rnd = (1 << (n - 1)) | (rnd_value << 1) | 1
    return odd_rnd



#Primality test using Solovay-Strassen probabilistic test.
#Worst case error bound is 1/2, but in practice is smaller.
def is_prime(n, sec_param):

    if n < 3:
        raise TypeError("n must be equal or larger than 3")
    if n & 1 == 0:
        return False
    elif n == 3 or n == 5:
        return True

    for i in range(sec_param):
        a = randint(2, n - 2)
        r = gmp.powmod(a, (n - 1) >> 1, n)

        if r != 1 and r != (n - 1):
            return False
        
        symbol = jacobi_symbol(a, n)
        if not gmp.is_congruent(r, symbol, n):
            return False
        
    return True


def getSafePrime(bits):
    if bits < 15:
        raise TypeError("Argument must be at least 15")
    
    while True:
        loop_again = False
        rnd_value = odd_random(bits-1) 

        #All safe primes are congruent to 11 mod 12,
        #so our random value must be congruent to 5 mod 6.
        rnd_value -= gmp.f_mod(rnd_value + 1,6)
        if gmp.bit_length(rnd_value) < bits-1:  
            continue

        #We check the value for small divisors before
        #applying more expansive tests, and also check
        #if rnd_value mod prime == (prime-1)/2 according
        #to https://eprint.iacr.org/2003/186.pdf.
        for x in prime_set[:1000]:
            remainder = gmp.f_mod(rnd_value,x)
            if remainder == 0 or remainder == ((x-1) >> 1):
                loop_again = True
                break
        
        if loop_again is True:
            continue
        
        cast_value = int(rnd_value)
        prob_safe_prime = (cast_value << 1) + 1

        if not is_prime(cast_value, 20):
            continue
        if not is_prime(prob_safe_prime, 20):
            continue

        return prob_safe_prime


        
        



        
    

    
    
    

        
        
        
        
        
           
        








