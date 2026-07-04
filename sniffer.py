from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        scr_ip = packet[IP].scr
        dst_ip = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else " OTHER"
        size = len(packet)

        if TCP in packet:
            port = packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].dport
        else:
            port = None

        print(f"[PACKET] {src_ip} -> {dst_ip} | Proto: {proto} | Port: {port} | Size: {size} bytes")

print("[*] Starting packet capture on eth0...")
print("[*] Pres Ctrl+C to stop\n")

sniff(iface="eth0", prn=process_packet, store=False)
