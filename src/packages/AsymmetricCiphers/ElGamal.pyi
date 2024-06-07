import gmpy2 as gmp
from typing import Tuple, Optional

class ElGamalBase:
    bits: int
    predefined_group: bool
    modulus: Optional[int]
    q: Optional[int]
    generator: Optional[int]
    __priv_key: Optional[int]
    __pub_key: Optional[int]

    def __init__(self, bits: int, predefined_group: bool = False) -> None: ...
    
    def generate_keys(self) -> None: ...
    
    def set_keys(self, public: int, private: int) -> None: ...
    
    def generate_params(self, group_params: Optional[Tuple[int, int]] = None) -> None: ...
    
    def _validate_and_set_params(self, group_params: Tuple[int, int]) -> None: ...
    
    def re_encrypt(self, ciphertext: Tuple[int, int], rnd_value: int, key: int) -> Tuple[int, int]: ...
    
    def homomorphic_mul(self, ciphertext_a: Tuple[int, int], ciphertext_b: Tuple[int, int]) -> Tuple[int, int]: ...
    
    @property
    def priv_key(self) -> Optional[int]: ...
    
    @property
    def pub_key(self) -> Optional[int]: ...


class MulElGamal(ElGamalBase):

    def __init__(self, bits: int, predefined_group: bool = False) -> None: ...
    
    def encrypt(self, plaintext: int, key: int) -> Tuple[int, int]: ...
    
    def decrypt(self, ciphertext: Tuple[int, int]) -> int: ...


class AddElGamal(ElGamalBase):

    beta: Optional[int]

    def __init__(self, bits: int, predefined_group: bool = False) -> None: ...
    
    def generate_params(self, group_params: Optional[Tuple[int, int, int]] = None) -> None: ...
    
    def _validate_and_set_params(self, group_params: Tuple[int, int, int]) -> None: ...
    
    def encrypt(self, plaintext: int, key: int) -> Tuple[int, int]: ...
    
    def decrypt(self, ciphertext: Tuple[int, int]) -> int: ...
