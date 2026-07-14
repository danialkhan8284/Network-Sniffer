import socket
import time
from parser import PacketParser


ETH_P_ALL = 0x0003
BUFFER_SIZE = 65535


class NetworkSniffer:

    def __init__(self, interface):

        self.interface = interface

        self.socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL)
        )

        self.socket.bind((self.interface, 0))

        self.parser = PacketParser()

    def receive_packet(self):

        raw_packet = self.socket.recvfrom(BUFFER_SIZE)[0]

        return raw_packet

    def start(self, packet_limit):

        print(f"\nListening on {self.interface}...\n")

        packet_number = 1

        while packet_number <= packet_limit:

            try:

                raw_packet = self.receive_packet()

                print("=" * 60)
                print(f"Packet #{packet_number}")

                self.parser.parse(raw_packet)

                packet_number += 1

                time.sleep(0.05)

            except KeyboardInterrupt:

                print("\nStopping Sniffer...")
                break

            except Exception as e:

                print("Error :", e)

        self.socket.close()

        print("\nCapture Finished.")