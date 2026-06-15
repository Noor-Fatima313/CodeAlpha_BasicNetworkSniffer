
from scapy.all import sniff, IP, TCP, UDP, ICMP


def process_packet(packet):
    print("\n" + "=" * 60)

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        # Detect protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"

        print(f"Protocol       : {protocol}")

        # Show payload if available
        if packet.payload:
            payload = bytes(packet.payload)
            print(f"Payload Length : {len(payload)} bytes")

            try:
                print("Payload Data:")
                print(payload[:100])
            except:
                print("Unable to decode payload")


print("====================================")
print(" Basic Network Sniffer Started")
print(" Capturing 20 packets...")
print("====================================")

sniff(prn=process_packet, count=20)

print("\nPacket capture completed.")