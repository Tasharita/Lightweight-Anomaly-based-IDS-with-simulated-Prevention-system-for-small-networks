from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

packet_counts = defaultdict(int)
port_tracker = defaultdict(set)

window_start = time.time()
WINDOW = 10

def process_packet(packet):
    global window_start
    if IP in packet:
        src = packet[IP].src
        packet_counts[src] +=1

        if TCP in packet:
            port_tracker[src].add(packet[TCP].dport)
        elif UDP in packet:
            port_tracker[src].add(packet[UDP].dport)

        if time.time() - window_start >= WINDOW:
            print("\n--- Baseline window ---")

            for ip in packet_counts:
                count = packet_counts[ip]
                num_ports = len(port_tracker[ip])
                print(f" IP:{ip} | Packets: {count} | Unique ports: {num_ports}")
            packet_counts.clear()
            port_tracker.clear()
            window_start = time.time()

print("[*] Capturing baseline traffic for 60 seconds...")
print("[*] Do NOT run any attacks during this time\n")
sniff(iface="eth0", prn=process_packet, store=False, timeout=60)
print("\n[*] Baseline capture complete")

