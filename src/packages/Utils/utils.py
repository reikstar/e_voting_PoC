import base64
from packages.Utils.RFC3526Groups import dh_groups

def hex_to_base64(hex_string):
    hex_string = hex_string.replace(" ", "").replace("\n", "")
    byte_array = bytes.fromhex(hex_string)
    return base64.b64encode(byte_array).decode('utf-8')


def get_rfc_group(id):
    
    if id not in dh_groups:
        grp_id = [x for x in dh_groups]
        raise AttributeError(f"""Group id is not existing in list.
                Id available:{grp_id}""")
    
    bits = dh_groups[id].get("bits")
    hex_string = dh_groups[id].get("hex_value").replace(" ", "").replace("\n", "")
    modulus = int(hex_string, 16)
    generator = dh_groups[id].get("generator")
    
    return (bits, modulus, generator)




