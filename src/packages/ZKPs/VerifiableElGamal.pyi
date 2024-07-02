from typing import Optional, Tuple, List, Any

K: int

def decryption_proof(
    p: int,
    q: int,
    generator: int,
    priv_key: int,
    pub_key: int,
    plaintext: int,
    ciphertext: Tuple[int, int],
    other_info: Optional[Any] = None,
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
    other_info: Optional[Any] = None,
) -> bool: ...
def re_encryption_proof(
    p: int,
    q: int,
    generator: int,
    verifier_pub_key: int,
    pub_key: int,
    r_enc_factor: int,
    ciphertext: Tuple[int, int],
    r_enc_ciphertext: Tuple[int, int],
    other_info: Optional[Any] = None,
) -> Tuple[List[int], List[int]]: ...
def re_encryption_verify(
    p: int,
    q: int,
    generator: int,
    verifier_pub_key: int,
    pub_key: int,
    commitment: List[int],
    response: List[int],
    ciphertext: Tuple[int, int],
    r_enc_ciphertext: Tuple[int, int],
    other_info: Optional[Any] = None,
) -> bool: ...
def re_encryption_or_proof(
    p: int,
    q: int,
    generator: int,
    pub_key: int,
    ciphertext: Tuple[int, int],
    r_enc_index: int,
    r_enc_factor: int,
    encryption_list: List[Tuple[int, int]],
    other_info: Optional[Any] = None,
) -> Tuple[List[Tuple[int, int]], Tuple[List[int], List[int]]]: ...
def re_encryption_or_verify(
    p: int,
    q: int,
    generator: int,
    pub_key: int,
    ciphertext: Tuple[int, int],
    encryption_list: List[Tuple[int, int]],
    commitment: List[Tuple[int, int]],
    response: Tuple[List[int], List[int]],
    other_info: Optional[Any] = None,
) -> bool: ...
