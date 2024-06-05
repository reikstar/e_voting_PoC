import base64

def hex_to_base64(hex_string):
    hex_string = hex_string.replace(" ", "").replace("\n", "")
    byte_array = bytes.fromhex(hex_string)
    return base64.b64encode(byte_array).decode('utf-8')