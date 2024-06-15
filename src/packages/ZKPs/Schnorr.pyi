from typing import Any, Optional, Tuple

def generate_proof(
    p: int,
    q: int,
    generator: int,
    priv_key: int,
    pub_key: int,
    other_info: Optional[Any] = None,
) -> Tuple[int, int]: ...
def verify_proof(
    p: int,
    q: int,
    generator: int,
    pub_key: int,
    commitment: int,
    response: int,
    other_info: Optional[Any] = None,
) -> bool: ...
