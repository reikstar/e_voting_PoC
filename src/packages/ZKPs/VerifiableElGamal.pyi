from typing import Optional, Tuple, List

K: int

def decryption_proof(
    p: int,
    q: int,
    generator: int,
    priv_key: int,
    pub_key: int,
    plaintext: int,
    ciphertext: Tuple[int, int],
    other_info: Optional[str] = None,
) -> Tuple[List[int], int]: ...
def decryption_verify(
    p: int,
    q: int,
    generator: int,
    pub_key: int,
    commitment: List[int],
    response: int,
    plaintext: int,
    ciphertext: Tuple[int, int],
    other_info: Optional[str] = None,
) -> bool: ...
