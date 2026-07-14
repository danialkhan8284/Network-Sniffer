# utils.py

def format_mac(mac_bytes):

    return ':'.join('{:02x}'.format(byte) for byte in mac_bytes)