# e_voting_PoC
Proof of concept of ZKP's utility in electronic voting.

We provided an implementation of https://link.springer.com/chapter/10.1007/3-540-45539-6_38 .

Cryptosystem used: Additive Homomorphic ElGamal.
ZKP's used: -Verifiable Secret Sharing
            -Schnorr's Identification Protocol
            -Designated Verifier Re-encryption Proof
            -1-out-of-K Re-encryption Proof
            -Verifiable Threshold ElGamal

We also provided mathematical primitives, such as Solovay-Strassen primality test, fast K-ary exponentation algorithm, fast Safe-Prime generator.
