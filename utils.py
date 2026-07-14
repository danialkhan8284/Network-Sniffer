from colorama import Fore, Style
from matplotlib import colors


def format_mac(mac):

    return ":".join("{:02x}".format(x) for x in mac)


def get_port_name(port):

    ports = {

        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        389: "LDAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-ALT"

    }

    return ports.get(port, "Unknown")


def tcp_flags(flags):

    result = []

    if flags & 0x01:
        result.append("FIN")

    if flags & 0x02:
        result.append("SYN")

    if flags & 0x04:
        result.append("RST")

    if flags & 0x08:
        result.append("PSH")

    if flags & 0x10:
        result.append("ACK")

    if flags & 0x20:
        result.append("URG")

    if flags & 0x40:
        result.append("ECE")

    if flags & 0x80:
        result.append("CWR")

    return " | ".join(result)


def protocol_color(protocol):

    colors = {

        "TCP": Fore.GREEN,

        "UDP": Fore.BLUE,

        "ICMP": Fore.YELLOW

    }
    return colors.get(protocol, Fore.WHITE)
def hexdump(data, length=16):

    for i in range(0, len(data), length):

        chunk = data[i:i+length]

        hex_data = " ".join("{:02X}".format(x) for x in chunk)

        ascii_data = ""

        for byte in chunk:

            if 32 <= byte <= 126:

                ascii_data += chr(byte)

            else:

                ascii_data += "."

        print(f"{i:04X}  {hex_data:<48} {ascii_data}")

    