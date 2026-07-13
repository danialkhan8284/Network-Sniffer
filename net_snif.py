import socket
import struct
import binascii
import time
import datetime

# Define constants
ETH_P_ALL = 0x0003  # Capture all protocols
BUF_SIZE = 65535    # Buffer size for packet capture

class NetworkSniffer:
    def __init__(self, interface=None):
        self.interface = interface or 'eth0'  # Default to eth0
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        if interface:
            self.sock.bind((interface, 0))
    
    def dissect_ethernet(self, eth_header):
        """Dissect Ethernet header"""
        eth = struct.unpack("!6s6sH", eth_header)
        return {
            'dst_mac': binascii.hexlify(eth[0]).decode(),
            'src_mac': binascii.hexlify(eth[1]).decode(),
            'eth_type': eth[2]
        }
    
    def dissect_ip(self, ip_header):
        """Dissect IP header"""
        ip = struct.unpack("!BBHHHBBH4s4s", ip_header)
        return {
            'version': ip[0] >> 4,
            'ihl': ip[0] & 0xF,
            'tos': ip[1],
            'length': ip[2],
            'id': ip[3],
            'flags': ip[4] >> 13,
            'offset': ip[4] & 0x1FFF,
            'ttl': ip[5],
            'protocol': ip[6],
            'checksum': ip[7],
            'src_ip': socket.inet_ntoa(ip[8]),
            'dst_ip': socket.inet_ntoa(ip[9])
        }
    
    def dissect_tcp(self, tcp_header):
        """Dissect TCP header"""
        tcp = struct.unpack("!HHLLBBHHH", tcp_header)
        return {
            'src_port': tcp[0],
            'dst_port': tcp[1],
            'seq': tcp[2],
            'ack': tcp[3],
            'offset': tcp[4] >> 4,
            'flags': tcp[4] & 0xF,
            'window': tcp[5],
            'checksum': tcp[6],
            'urgent': tcp[7]
        }
    
    def analyze_packet(self, raw_data):
        """Analyze captured packet"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Dissect Ethernet header
        eth_header = raw_data[:14]
        eth = self.dissect_ethernet(eth_header)
        
        # Skip if not IP
        if eth['eth_type'] != 0x0800:
            return
        
        # Dissect IP header
        ip_header = raw_data[14:34]
        ip = self.dissect_ip(ip_header)
        
        # Dissect TCP header
        tcp_header = raw_data[34:54]
        tcp = self.dissect_tcp(tcp_header)
        
        # Display packet info
        print(f"\n[{timestamp}] Packet Analysis:")
        print(f"Ethernet: {eth['src_mac']} -> {eth['dst_mac']} ({eth['eth_type']})")
        print(f"IP: {ip['src_ip']} -> {ip['dst_ip']} (Protocol: {ip['protocol']})")
        print(f"TCP: {tcp['src_port']} -> {tcp['dst_port']} (Flags: {tcp['flags']})")
    
    def sniff(self, count=10):
        """Capture network packets"""
        print(f"Starting network sniffer on {self.interface}...")
        print(f"Capturing {count} packets...\n")
        
        for _ in range(count):
            try:
                raw_data = self.sock.recvfrom(BUF_SIZE)[0]
                self.analyze_packet(raw_data)
                time.sleep(0.1)  # Small delay
            except KeyboardInterrupt:
                print("\nStopping sniffer...")
                break
            except Exception as e:
                print(f"Error: {e}")
        
        self.sock.close()
        print("\nSniffing completed.")

if __name__ == "__main__":
    sniffer = NetworkSniffer()
    sniffer.sniff(count=20)