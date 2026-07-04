from scapy.all import sniff, IP,TCP,UDP
from collections import defaultdict
import time
import threading
import pandas as pd
import os

# --- Thresholds ---
PACKET_THRESHOLD = 500   # packets per 10 seconds -> DoS detection
PORT_THRESHOLD = 300     # unique ports per 10 seconds -> port scan detection
TIME_WINDOW = 10         # seconds

# --- counters ----
packet_counts = defaultdict(int)
port_tracker = defaultdict(set)
blacklist = set()
blocked_notice_shown = set()
alerts = []

# --- Whitelist ----
WHITELIST = {"192.168.56.105", "192.168.56.107", "192.168.56.1"}

# ---lock for thread safety ---
lock = threading.Lock()

window_start = time.time()

# --- Log Alert to CSV ---
def log_alert(ip, anomaly_type, value):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    alert = {
        "Timestamp": timestamp,
        "Source IP": ip,
        "Anomaly Type": anomaly_type,
        "Value": value
    }
    alerts.append(alert)
    df = pd.DataFrame([alert])
    if not os.path.exists("alerts.csv"):
        df.to_csv("alerts.csv", index=False)
    else:
        df.to_csv("alerts.csv", mode="a", header=False, index=False)
    print("\n[ALERT]" + timestamp + "|" + ip + "|" + anomaly_type + "| Value:" + str(value))
    print(f"[BLACKLIST]" + ip + " has been flagged and blacklisted")

# --- Packet Handler ---
def process_packet(packet):
    global window_start

    if IP in packet:
        src = packet[IP].src

        # ignore from blacklisted IPs
        if src in blacklist:
            return

        with lock:
            # update counters
            packet_counts[src] += 1

            if TCP in packet:
                tcp_flags = packet[TCP].flags


                # Count only SYN packets
                if tcp_flags == 0x02:
                    port_tracker[src].add(packet[TCP].dport)
            elif UDP in packet:
                port_tracker[src].add(packet[UDP].dport)

            # check if time window has ended
            if time.time() - window_start >= TIME_WINDOW:
                check_thresholds()
                packet_counts.clear()
                port_tracker.clear()
                window_start = time.time()


# --- Detection logic ---
def check_thresholds():
    for ip, count in packet_counts.items():
        if ip in WHITELIST:
            continue
        if count > PACKET_THRESHOLD and ip not in blacklist:
            blacklist.add(ip)
            log_alert(ip,"DOS / TRAFFIC SPIKE", count)

    for ip,ports in port_tracker.items():
        if len(ports) > PORT_THRESHOLD and ip not in blacklist:
            blacklist.add(ip)
            log_alert(ip, "PORT SCAN", len(ports))

# --- Main ---
print("=" * 55)
print(" Lightweight Anomaly-Based IDS")
print(" Monitoring traffic on eth0...")
print(f" DoS Threshold:       {PACKET_THRESHOLD} packets / {TIME_WINDOW}s")
print(f" Port Scan Threshold: {PORT_THRESHOLD} unique ports / {TIME_WINDOW}s")
print("=" * 55)
print("[*] Press ctrl+C to stop\n")

try:
    sniff(iface="eth0", prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\n[*] Stopping IDS...")
    if alerts:
        print(f"[*] {len(lerts)} alerts logged to alerts.csv")
    else:
        print("[*] No alerts generated")
    print("[*] IDS stopped")
