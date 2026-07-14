from sniffer import NetworkSniffer


def main():
    print("=" * 60)
    print(" Advanced Network Packet Sniffer")
    print(" Python Cyber Security Project")
    print("=" * 60)

    interface = input("Enter Interface (Default: eth0): ").strip()

    if interface == "":
        interface = "eth0"

    packet_count = input("Number of packets to capture (Default: 20): ").strip()

    if packet_count == "":
        packet_count = 20
    else:
        packet_count = int(packet_count)

    sniffer = NetworkSniffer(interface)
    sniffer.start(packet_count)


if __name__ == "__main__":
    main()