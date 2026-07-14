

PROTOCOLS = {

    1: "ICMP",

    2: "IGMP",

    6: "TCP",

    17: "UDP",

    41: "IPv6",

    47: "GRE",

    50: "ESP",

    51: "AH",

    58: "ICMPv6",

    89: "OSPF"

}


def protocol_name(number):

    return PROTOCOLS.get(number, f"Unknown ({number})")