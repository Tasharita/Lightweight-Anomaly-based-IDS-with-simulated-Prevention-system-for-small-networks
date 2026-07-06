from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        print(f"[PACKET] From: {src}")
        if TCP in packet:
            flags = packet[TCP].flags
            port = packet[TCP].dport
            print(f"  TCP | Port: {port} | Flags: {flags}")

print("[*] Debug sniffer running on eth0...")
print("[*] Waiting for packets...\n")
sniff(iface="eth0", prn=process_packet, store=False)
