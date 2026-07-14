import socket
import struct
from protocols import protocol_name
from utils import format_mac
from logger import PacketLogger


class PacketParser:
    
    def __init__(self):
        self.logger = PacketLogger()
 

    def parse(self, raw_data):

        # -------------------------------
        # Ethernet Header
        # -------------------------------

        ethernet = struct.unpack("!6s6sH", raw_data[:14])

        destination_mac = format_mac(ethernet[0])
        source_mac = format_mac(ethernet[1])
        eth_protocol = socket.ntohs(ethernet[2])

        print("\n========== Ethernet ==========")
        print(f"Source MAC      : {source_mac}")
        print(f"Destination MAC : {destination_mac}")
        print(f"EtherType       : {hex(eth_protocol)}")

        # Sirf IPv4 ko parse karenge
        if eth_protocol != 0x0800:
            print("Non IPv4 Packet")
            return

        # -------------------------------
        # IP Header
        # -------------------------------

        ip_header = raw_data[14:34]

        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        version = iph[0] >> 4
        ihl = iph[0] & 15

        ttl = iph[5]

        protocol = iph[6]

        source_ip = socket.inet_ntoa(iph[8])
        destination_ip = socket.inet_ntoa(iph[9])

        print("\n========== IPv4 ==========")
        print(f"Version         : {version}")
        print(f"Header Length   : {ihl*4} Bytes")
        print(f"TTL             : {ttl}")
        print(f"Protocol        : {protocol_name(protocol)}")
        print(f"Source IP       : {source_ip}")
        print(f"Destination IP  : {destination_ip}")
        
        # Save packet information into log file
        self.logger.write(
          f"{source_ip} -> {destination_ip} | {protocol_name(protocol)}"
       )
        
                


        # -------------------------------
        # TCP
        # -------------------------------
        
        

        if protocol == 6:

            tcp_start = 14 + (ihl * 4)

            tcp_header = raw_data[tcp_start:tcp_start+20]

            tcph = struct.unpack("!HHLLBBHHH", tcp_header)

            source_port = tcph[0]
            destination_port = tcph[1]

            sequence = tcph[2]
            acknowledgement = tcph[3]

            offset = (tcph[4] >> 4) * 4

            flags = tcph[5]

            print("\n========== TCP ==========")
            print(f"Source Port     : {source_port}")
            print(f"Destination Port: {destination_port}")
            print(f"Sequence Number : {sequence}")
            print(f"Ack Number      : {acknowledgement}")
            print(f"Header Length   : {offset} Bytes")
            print(f"Flags           : {flags}")

        elif protocol == 17:

            udp_start = 14 + (ihl * 4)

            udp_header = raw_data[udp_start:udp_start+8]

            udph = struct.unpack("!HHHH", udp_header)

            print("\n========== UDP ==========")
            print(f"Source Port     : {udph[0]}")
            print(f"Destination Port: {udph[1]}")
            print(f"Length          : {udph[2]}")

        elif protocol == 1:

            icmp_start = 14 + (ihl * 4)

            icmp_header = raw_data[icmp_start:icmp_start+4]

            icmph = struct.unpack("!BBH", icmp_header)

            print("\n========== ICMP ==========")
            print(f"Type            : {icmph[0]}")
            print(f"Code            : {icmph[1]}")

        print("\n")
        
