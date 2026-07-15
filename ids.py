from scapy.all import sniff, IP,TCP,UDP
from collections import defaultdict
import time
import threading
import pandas as pd
import os
import subprocess

# ── LOAD WHITELIST ──
WHITELIST_FILE = "whitelist.txt"

def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as f:
            ips = set()
            for line in f:
                line = line.strip()
                if line:
                    ip = line.split(",")[0].strip()
                    ips.add(ip)
            return ips
    return set()

WHITELIST = load_whitelist()
print(f"Loaded whitelist: {WHITELIST}")
# --- Thresholds ---
PACKET_THRESHOLD = 50   # packets per 10 seconds -> DoS detection
PORT_THRESHOLD = 50     # unique ports per 10 seconds -> port scan detection
TIME_WINDOW = 5         # seconds

# --- counters ----
packet_counts = defaultdict(int)
port_tracker = defaultdict(set)
blacklist = set()
blocked_notice_shown = set()
alerts = []


# ---lock for thread safety ---
lock = threading.Lock()

window_start = time.time()

# --- Log Alert to CSV ---
def log_alert(ip, anomaly_type, value):
    print(">>> LOG ALERT CALLED")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    alert = {
        "Timestamp": timestamp,
        "Source IP": ip,
        "Anomaly Type": anomaly_type,
        "Value": value
    }
    alerts.append(alert)
    df = pd.DataFrame([alert])
    if not os.path.exists("/home/tasha/ids_project/alerts.csv"):
        df.to_csv("/home/tasha/ids_project/alerts.csv", index=False)
    else:
        df.to_csv("/home/tasha/ids_project/alerts.csv", mode="a", header=False, index=False)
    print("\n[ALERT]" + timestamp + "|" + ip + "|" + anomaly_type + "| Value:" + str(value))
    print(f"[BLACKLIST]" + ip + " has been flagged and blacklisted")


def block_ip(ip):

    try:
        subprocess.run([
            "iptables",
            "-A",
            "INPUT",
            "-s",
            ip,
            "-j",
            "DROP"
        ], check=True)

        print(f"[BLOCKED] {ip} has been blocked using iptables")

    except Exception as e:
        print(f"[ERROR] Failed to block {ip}: {e}")

# --- Packet Handler ---
def process_packet(packet):
    global window_start

    if IP in packet:
        src = packet[IP].src

        # Ignore trusted devices
        if src in WHITELIST:
            return

        # Ignore already-blacklisted IPs
        if src in blacklist:
            return

        with lock:

            # Count packets
            packet_counts[src] += 1

            # Track destination ports
            if TCP in packet:

                # Only count SYN packets
                port_tracker[src].add(packet[TCP].dport)

            elif UDP in packet:
                port_tracker[src].add(packet[UDP].dport)

            # ----- Immediate Port Scan Detection -----
            if len(port_tracker[src]) >= PORT_THRESHOLD:

                blacklist.add(src)
                block_ip(src)
                log_alert(src, "PORT SCAN", len(port_tracker[src]))

                return


            # ----- Immediate DoS Detection -----
            if packet_counts[src] >= PACKET_THRESHOLD:

                blacklist.add(src)
                block_ip(src)
                log_alert(src, "DOS / TRAFFIC SPIKE", packet_counts[src])

                return

            # Check thresholds every time window
            if time.time() - window_start >= TIME_WINDOW:
                packet_counts.clear()
                port_tracker.clear()
                window_start = time.time()


# --- Main ---
print("=" * 60)
print("      Lightweight Anomaly-Based IDS")
print("=" * 60)

print(f"Monitoring Interface : eth0")
print(f"Detection Window     : {TIME_WINDOW} seconds")
print(f"DoS Threshold        : {PACKET_THRESHOLD} packets")
print(f"Port Scan Threshold  : {PORT_THRESHOLD} unique ports")
print()

print(f"Trusted Hosts Loaded : {len(WHITELIST)}")

for ip in sorted(WHITELIST):
    print(f"   ✓ {ip}")

print()

print("[*] Monitoring started...")
print("[*] Press Ctrl+C to stop.\n")

try:
    sniff(iface="eth0", prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\n[*] Stopping IDS...")
    if alerts:
        print(f"[*] {len(alerts)} alerts logged to alerts.csv")
    else:
        print("[*] No alerts generated")

    print(f"[*] Blacklisted IPs: {len(blacklist)}")
    print("[*] IDS stopped")


