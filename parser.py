import socket
import struct
import datetime

from colorama import Fore, Style

from protocols import protocol_name
from utils import (
    format_mac,
    get_port_name,
    tcp_flags,
    protocol_color,
    hexdump
)
from logger import PacketLogger


class PacketParser:

    def __init__(self):

        self.logger = PacketLogger()

    def parse(self, raw_data):

        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        packet_size = len(raw_data)

        print(Fore.CYAN + "=" * 60)
        print(f"[{timestamp}] Packet Size : {packet_size} Bytes")
        print("=" * 60 + Style.RESET_ALL)

        # ---------------------------------
        # Ethernet Header
        # ---------------------------------

        ethernet = struct.unpack("!6s6sH", raw_data[:14])

        destination_mac = format_mac(ethernet[0])
        source_mac = format_mac(ethernet[1])

        eth_protocol = socket.ntohs(ethernet[2])

        print(Fore.MAGENTA + "\n========== Ethernet ==========" + Style.RESET_ALL)

        print(f"Source MAC       : {source_mac}")
        print(f"Destination MAC  : {destination_mac}")
        print(f"EtherType        : {hex(eth_protocol)}")

        if eth_protocol != 0x0800:
            print("Non IPv4 Packet\n")
            return

        # ---------------------------------
        # IPv4 Header
        # ---------------------------------

        ip_header = raw_data[14:34]

        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        version = iph[0] >> 4

        ihl = iph[0] & 15

        ip_header_length = ihl * 4

        ttl = iph[5]

        protocol = iph[6]

        source_ip = socket.inet_ntoa(iph[8])

        destination_ip = socket.inet_ntoa(iph[9])

        protocol_text = protocol_name(protocol)

        print(Fore.GREEN + "\n========== IPv4 ==========" + Style.RESET_ALL)

        print(f"Version          : {version}")
        print(f"Header Length    : {ip_header_length} Bytes")
        print(f"TTL              : {ttl}")
        print(f"Protocol         : {protocol_text}")
        print(f"Source IP        : {source_ip}")
        print(f"Destination IP   : {destination_ip}")

        self.logger.write(
            f"{source_ip} -> {destination_ip} | {protocol_text}"
        )

        # ---------------------------------
        # TCP
        # ---------------------------------

        if protocol == 6:

            tcp_start = 14 + ip_header_length

            tcp_header = raw_data[tcp_start:tcp_start + 20]

            tcph = struct.unpack("!HHLLBBHHH", tcp_header)

            source_port = tcph[0]

            destination_port = tcph[1]

            sequence = tcph[2]

            acknowledgement = tcph[3]

            offset = (tcph[4] >> 4) * 4

            flags = tcph[5]

            print(
                protocol_color(protocol_text)
                + "\n========== TCP =========="
                + Style.RESET_ALL
            )

            print(f"Source Port      : {source_port} ({get_port_name(source_port)})")

            print(f"Destination Port : {destination_port} ({get_port_name(destination_port)})")

            print(f"Sequence Number  : {sequence}")

            print(f"Ack Number       : {acknowledgement}")

            print(f"Header Length    : {offset} Bytes")

            print(f"TCP Flags        : {tcp_flags(flags)}")

            payload_start = tcp_start + offset

            payload = raw_data[payload_start:]

            print(f"Payload Size     : {len(payload)} Bytes")

            try:

                http = payload.decode(errors="ignore")

                if http.startswith("GET"):

                    print(Fore.YELLOW + "\nHTTP GET Request" + Style.RESET_ALL)

                    print(http.split("\r\n")[0])

                elif http.startswith("POST"):

                    print(Fore.YELLOW + "\nHTTP POST Request" + Style.RESET_ALL)

                    print(http.split("\r\n")[0])

                elif http.startswith("HTTP"):

                    print(Fore.YELLOW + "\nHTTP Response" + Style.RESET_ALL)

                    print(http.split("\r\n")[0])

            except:
                pass

            print(Fore.CYAN + "\nHex Dump" + Style.RESET_ALL)

            hexdump(payload[:128])
            
                    # ---------------------------------
        # UDP
        # ---------------------------------

        elif protocol == 17:

            udp_start = 14 + ip_header_length

            udp_header = raw_data[udp_start:udp_start + 8]

            udph = struct.unpack("!HHHH", udp_header)

            source_port = udph[0]
            destination_port = udph[1]
            length = udph[2]

            print(
                Fore.BLUE
                + "\n========== UDP =========="
                + Style.RESET_ALL
            )

            print(f"Source Port      : {source_port} ({get_port_name(source_port)})")
            print(f"Destination Port : {destination_port} ({get_port_name(destination_port)})")
            print(f"Length           : {length}")

            payload = raw_data[udp_start + 8:]

            print(f"Payload Size     : {len(payload)} Bytes")

            print(Fore.CYAN + "\nHex Dump" + Style.RESET_ALL)

            hexdump(payload[:128])

        # ---------------------------------
        # ICMP
        # ---------------------------------

        elif protocol == 1:

            icmp_start = 14 + ip_header_length

            icmp_header = raw_data[icmp_start:icmp_start + 4]

            icmph = struct.unpack("!BBH", icmp_header)

            icmp_type = icmph[0]
            icmp_code = icmph[1]

            print(
                Fore.YELLOW
                + "\n========== ICMP =========="
                + Style.RESET_ALL
            )

            print(f"Type             : {icmp_type}")
            print(f"Code             : {icmp_code}")

            payload = raw_data[icmp_start + 4:]

            print(f"Payload Size     : {len(payload)} Bytes")

            print(Fore.CYAN + "\nHex Dump" + Style.RESET_ALL)

            hexdump(payload[:128])

        # ---------------------------------
        # Other Protocols
        # ---------------------------------

        else:

            print(
                Fore.RED
                + f"\nProtocol {protocol_text} is not implemented yet."
                + Style.RESET_ALL
            )

        print("\n" + "=" * 60 + "\n")